/********************************************************************
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 */
#include "utilstrencodings.h"
#include "uint256.h"
#include "mmr.h"
#include <inttypes.h>
#include <stdexcept>
#include <cstddef>
#include <cstring>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Expands each byte into two uppercase ASCII hex nibble characters.
// e.g. {0xAB} -> {'A','B'}
// This is the "nibble" representation used throughout the Patricia proof code.
static std::vector<unsigned char> bytesToNibbles(const unsigned char* data, size_t len)
{
    static const char kHex[] = "0123456789ABCDEF";
    std::vector<unsigned char> out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(static_cast<unsigned char>(kHex[data[i] >> 4]));
        out.push_back(static_cast<unsigned char>(kHex[data[i] & 0xf]));
    }
    return out;
}

static inline std::vector<unsigned char> bytesToNibbles(const std::vector<unsigned char>& v)
{
    return bytesToNibbles(v.data(), v.size());
}

// Decode a big-endian byte span into a size_t length value.
static size_t decodeBELength(const unsigned char* p, size_t n)
{
    size_t val = 0;
    for (size_t i = 0; i < n; i++)
        val = (val << 8) | p[i];
    return val;
}

// Minimal big-endian encoding of a uint64.  Zero is encoded as an empty vector.
static std::vector<unsigned char> uint64ToBEVec(uint64_t v)
{
    std::vector<unsigned char> out;
    while (v) {
        out.push_back(static_cast<unsigned char>(v & 0xFF));
        v >>= 8;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

// ---------------------------------------------------------------------------
// Deprecated pre-fork helpers — preserved exactly for on-chain compatibility.
// These deliberately reproduce the original encoding quirks so that proofs
// accepted before the optimizedProof fork height can still be verified.
// DO NOT "fix" these functions.
// ---------------------------------------------------------------------------

static std::string int_to_hex_deprecated(int input)
{
    std::stringstream sstream;
    if (input < 10) sstream << std::hex << 0;
    sstream << std::hex << input;
    return sstream.str();
}

static std::string uint64_to_hex_deprecated(uint64_t input)
{
    if (input < 10) {
        std::stringstream sstream;
        if (input < 10) sstream << std::hex << 0;
        sstream << std::hex << input;
        return sstream.str();
    }
    char buffer[64] = {0};
    snprintf(buffer, sizeof(buffer), "%" PRIx64, input);
    return std::string(buffer);
}

// Count how many leading nibble characters match between a and b.
static size_t matchingNibbleLength(const std::vector<unsigned char>& a,
                                   const std::vector<unsigned char>& b)
{
    size_t i = 0;
    while (i < a.size() && i < b.size() && a[i] == b[i])
        ++i;
    return i;
}

// ---------------------------------------------------------------------------
// TrieNode
// ---------------------------------------------------------------------------

TrieNode::nodeType TrieNode::setType()
{
    if (raw.size() == 17) return BRANCH;
    if (raw.size() == 2 && !raw[0].empty()) {
        // HP encoding: high nibble of first byte is the prefix.
        // 0,1 → extension; 2,3 → leaf.
        unsigned char prefix = raw[0][0] >> 4;
        return (prefix >= 2) ? LEAF : EXTENSION;
    }
    return BRANCH;
}

void TrieNode::setKey()
{
    if (type == BRANCH || raw[0].empty()) return;

    // Expand first element to ASCII nibble chars so we can strip the HP prefix.
    std::vector<unsigned char> nibbles = bytesToNibbles(raw[0]);

    // HP prefix parity: ASCII chars '0','2' (48,50) are even → skip 2 nibbles;
    // '1','3' (49,51) are odd → skip 1 nibble.
    size_t skip = (nibbles[0] % 2 == 0) ? 2u : 1u;
    key.assign(nibbles.begin() + skip, nibbles.end());
}

void TrieNode::setValue()
{
    if (type == BRANCH)
        // Slot 17 (raw[16]) holds the branch value when a key terminates here.
        value = (raw.size() == 17) ? raw[16] : std::vector<unsigned char>{};
    else
        value = raw[1];
}

// ---------------------------------------------------------------------------
// RLP encode
// ---------------------------------------------------------------------------

std::vector<unsigned char> RLP::encodeLength(int length, int offset)
{
    std::vector<unsigned char> out;
    if (length < 56) {
        out.push_back(static_cast<unsigned char>(length + offset));
    } else {
        // Encode length as minimal big-endian bytes.
        std::vector<unsigned char> lenBytes;
        int tmp = length;
        while (tmp > 0) {
            lenBytes.insert(lenBytes.begin(), static_cast<unsigned char>(tmp & 0xFF));
            tmp >>= 8;
        }
        out.push_back(static_cast<unsigned char>(offset + 55 + lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
    return out;
}

// Kept for binary compatibility with callers using optimized=false.
// Intentionally reproduces the original string-based encoding, including its
// known quirks (e.g. odd-length hex strings for certain lengths), so that
// pre-fork proofs accepted on-chain can still be verified identically.
// DO NOT replace this with a call to encodeLength().
std::vector<unsigned char> RLP::encodeLength_deprecated(int length, int offset)
{
    std::vector<unsigned char> output;
    if (length < 56) {
        output.push_back(length + offset);
    } else {
        std::string hexLength = int_to_hex_deprecated(length);
        int dataLength = static_cast<int>(hexLength.size()) / 2;
        std::string firstByte = int_to_hex_deprecated(offset + 55 + dataLength);
        std::string outputString = firstByte + hexLength;
        output = ParseHex(outputString);
    }
    return output;
}

std::vector<unsigned char> RLP::encode(std::vector<unsigned char> input)
{
    // Single bytes below 0x80 need no length prefix.
    if (input.size() == 1 && input[0] < 0x80) return input;

    std::vector<unsigned char> out = optimized
        ? encodeLength(static_cast<int>(input.size()), 0x80)
        : encodeLength_deprecated(static_cast<int>(input.size()), 0x80);
    out.insert(out.end(), input.begin(), input.end());
    return out;
}

std::vector<unsigned char> RLP::encode(std::vector<std::vector<unsigned char>> inputs)
{
    std::vector<unsigned char> payload;
    for (auto& item : inputs) {
        auto enc = encode(item);
        payload.insert(payload.end(), enc.begin(), enc.end());
    }
    std::vector<unsigned char> out = optimized
        ? encodeLength(static_cast<int>(payload.size()), 0xc0)
        : encodeLength_deprecated(static_cast<int>(payload.size()), 0xc0);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// ---------------------------------------------------------------------------
// RLP decode
// ---------------------------------------------------------------------------

RLP::rlpDecoded RLP::decode(std::vector<unsigned char> inputBytes, int depth)
{
    if (depth > MAX_RLP_DECODE_DEPTH)
        throw std::invalid_argument("RLP decode: maximum nesting depth exceeded");

    if (inputBytes.empty())
        throw std::invalid_argument("RLP decode: empty input");

    const unsigned char* p = inputBytes.data();
    const size_t total = inputBytes.size();
    const unsigned char first = p[0];

    rlpDecoded output;

    if (first <= 0x7f) {
        // Single byte string: the byte is its own value.
        output.data.push_back({first});
        output.remainder.assign(p + 1, p + total);

    } else if (first <= 0xb7) {
        // Short string: 0 to 55 bytes, length = first - 0x80.
        size_t strLen = static_cast<size_t>(first - 0x80);
        if (1 + strLen > total)
            throw std::invalid_argument("RLP decode: short string overflows input");
        if (strLen == 1 && p[1] < 0x80)
            throw std::invalid_argument("RLP decode: single byte < 0x80 must be self-encoded");
        output.data.push_back(std::vector<unsigned char>(p + 1, p + 1 + strLen));
        output.remainder.assign(p + 1 + strLen, p + total);

    } else if (first <= 0xbf) {
        // Long string: number of length bytes = first - 0xb7.
        size_t lenBytes = static_cast<size_t>(first - 0xb7);
        if (1 + lenBytes > total)
            throw std::invalid_argument("RLP decode: long string length overflows input");
        size_t strLen = decodeBELength(p + 1, lenBytes);
        // Use subtraction to avoid wrapping if strLen is near SIZE_MAX.
        if (strLen > total - 1 - lenBytes)
            throw std::invalid_argument("RLP decode: long string payload overflows input");
        output.data.push_back(std::vector<unsigned char>(p + 1 + lenBytes,
                                                          p + 1 + lenBytes + strLen));
        output.remainder.assign(p + 1 + lenBytes + strLen, p + total);

    } else if (first <= 0xf7) {
        // Short list: payload length = first - 0xc0.
        size_t listLen = static_cast<size_t>(first - 0xc0);
        if (1 + listLen > total)
            throw std::invalid_argument("RLP decode: short list payload overflows input");

        // Recursively decode each item inside the list.
        std::vector<unsigned char> inner(p + 1, p + 1 + listLen);
        while (!inner.empty()) {
            rlpDecoded sub = decode(inner, depth + 1);
            for (auto& d : sub.data)
                output.data.push_back(std::move(d));
            inner = std::move(sub.remainder);
        }
        output.remainder.assign(p + 1 + listLen, p + total);

    } else {
        // Long list: number of length bytes = first - 0xf7.
        size_t lenBytes = static_cast<size_t>(first - 0xf7);
        if (1 + lenBytes > total)
            throw std::invalid_argument("RLP decode: long list length overflows input");
        size_t listLen = decodeBELength(p + 1, lenBytes);
        size_t headerLen = 1 + lenBytes;
        // Use subtraction to avoid wrapping if listLen is near SIZE_MAX.
        if (listLen > total - headerLen)
            throw std::invalid_argument("RLP decode: long list payload overflows input");
        if (listLen == 0)
            throw std::invalid_argument("RLP decode: long list has zero-length payload");

        std::vector<unsigned char> inner(p + headerLen, p + headerLen + listLen);
        while (!inner.empty()) {
            rlpDecoded sub = decode(inner, depth + 1);
            for (auto& d : sub.data)
                output.data.push_back(std::move(d));
            inner = std::move(sub.remainder);
        }
        output.remainder.assign(p + headerLen + listLen, p + total);
    }

    return output;
}

RLP::rlpDecoded RLP::decode(std::string inputString)
{
    return decode(ParseHex(inputString));
}

// ---------------------------------------------------------------------------
// Patricia proof verification
// ---------------------------------------------------------------------------

// Walk the Merkle-Patricia proof from rootHash using the given key (raw bytes).
// Returns the leaf value found at the key, or throws std::invalid_argument on failure.
template<>
std::vector<unsigned char> CETHPATRICIABranch::verifyProof(
    uint256& rootHash,
    std::vector<unsigned char> key,
    std::vector<std::vector<unsigned char>>& proof)
{
    uint256 wantedHash = rootHash;
    RLP rlp;

    // Key is represented as ASCII uppercase hex nibble characters.
    key = bytesToNibbles(key);

    for (size_t i = 0; i < proof.size(); ++i) {
        const std::vector<unsigned char>& nodeBytes = proof[i];

        if (nodeBytes.empty())
            throw std::invalid_argument("RLP: empty proof node at i=" + std::to_string(i));

        // Each node must hash (keccak256) to the expected value.
        CKeccack256Writer writer;
        writer.write(reinterpret_cast<const char*>(nodeBytes.data()), nodeBytes.size());
        if (writer.GetHash() != wantedHash)
            throw std::invalid_argument("Bad proof node: i=" + std::to_string(i));

        TrieNode node(rlp.decode(nodeBytes).data);

        if (node.type == TrieNode::BRANCH) {
            if (key.empty()) {
                if (i != proof.size() - 1)
                    throw std::invalid_argument("Additional nodes after terminal branch");
                return node.value;
            }

            int nibbleIdx = HexDigit(static_cast<char>(key[0]));
            if (nibbleIdx < 0 || nibbleIdx >= 16)
                throw std::invalid_argument("Invalid nibble value in key");
            if (static_cast<size_t>(nibbleIdx) >= node.raw.size())
                throw std::invalid_argument("Branch node child index out of range");

            std::vector<unsigned char> child = node.raw[nibbleIdx];
            key.erase(key.begin()); // consume one nibble

            if (child.size() == wantedHash.size()) {
                // Full 32-byte hash — the child is identified by hash.
                memcpy(wantedHash.begin(), child.data(), child.size());
            } else if (!child.empty()) {
                // Inline (short) embedded node — decode it directly.
                TrieNode embeddedNode(rlp.decode(child).data);
                if (i != proof.size() - 1)
                    throw std::invalid_argument("Additional nodes after embedded branch terminal");
                if (matchingNibbleLength(embeddedNode.key, key) != embeddedNode.key.size())
                    throw std::invalid_argument("Key does not match embedded node key");
                key.erase(key.begin(), key.begin() + embeddedNode.key.size());
                if (!key.empty())
                    throw std::invalid_argument("Key not fully consumed after embedded node");
                return embeddedNode.value;
            } else {
                throw std::invalid_argument("Branch child is empty for the given key nibble");
            }

        } else if (node.type == TrieNode::EXTENSION || node.type == TrieNode::LEAF) {
            if (matchingNibbleLength(node.key, key) != node.key.size())
                throw std::invalid_argument("Key does not match node path at i=" + std::to_string(i));

            key.erase(key.begin(), key.begin() + node.key.size());
            const std::vector<unsigned char>& child = node.value;

            if (key.empty()) {
                // Reached the target node.
                if (i != proof.size() - 1)
                    throw std::invalid_argument("Additional nodes after leaf/extension terminal");
                return child;
            }

            // Extension: child must be a 32-byte hash pointing to the next node.
            if (child.size() != wantedHash.size())
                throw std::invalid_argument("Extension value is not a 32-byte hash");
            memcpy(wantedHash.begin(), child.data(), child.size());

        } else {
            throw std::invalid_argument("Invalid trie node type");
        }
    }

    // Proof nodes exhausted without reaching the key — malformed proof.
    throw std::invalid_argument("verifyProof: proof exhausted without reaching target key");
}

// ---------------------------------------------------------------------------
// CETHPATRICIABranch methods
// ---------------------------------------------------------------------------

template<>
std::vector<unsigned char> CETHPATRICIABranch::verifyAccountProof()
{
    if (proofdata.proof_branch.empty())
        throw std::invalid_argument("verifyAccountProof: account proof is empty");

    // Key = keccak256(address)
    CKeccack256Writer key_hasher;
    key_hasher.write(reinterpret_cast<const char*>(&address), address.size());
    uint256 key_hash = key_hasher.GetHash();
    std::vector<unsigned char> address_hash(key_hash.begin(), key_hash.end());

    try {
        // Derive the state root from the first (root) proof node, since we may
        // not have the authoritative state root from the notaries.
        CKeccack256Writer root_hasher;
        root_hasher.write(
            reinterpret_cast<const char*>(proofdata.proof_branch[0].data()),
            proofdata.proof_branch[0].size());
        stateRoot = root_hasher.GetHash();
        return verifyProof(stateRoot, address_hash, proofdata.proof_branch);
    } catch (const std::invalid_argument& e) {
        memset(&stateRoot, 0, stateRoot.size());
        throw std::invalid_argument(std::string("verifyAccountProof: ") + e.what());
    }
}

template<>
uint256 CETHPATRICIABranch::verifyStorageProof(uint256 ccExportHash, bool optimizedProof)
{
    RLP rlp(optimizedProof);

    // --- Step 1: verify storage proof and check the stored value ---
    try {
        // Storage key = keccak256(storageProofKey)
        CKeccack256Writer key_hasher;
        key_hasher.write(reinterpret_cast<const char*>(&storageProofKey),
                         storageProofKey.size());
        uint256 key_hash = key_hasher.GetHash();
        std::vector<unsigned char> keyVec(key_hash.begin(), key_hash.end());

        std::vector<unsigned char> storageValue =
            verifyProof(storageHash, keyVec, storageProof.proof_branch);

        if (storageValue.empty())
            throw std::invalid_argument("Storage proof returned empty value");

        // The stored value is RLP-encoded — decode it.
        RLP::rlpDecoded decoded = rlp.decode(storageValue);
        if (decoded.data.empty())
            throw std::invalid_argument("RLP decoded storage value is empty");

        // Proofs may be left-truncated; pad to 32 bytes.
        auto& val = decoded.data[0];
        while (val.size() < 32)
            val.insert(val.begin(), 0x00);

        std::vector<unsigned char> expectedHash(ccExportHash.begin(), ccExportHash.end());
        if (val != expectedHash)
            throw std::invalid_argument("RLP Storage Value does not match expected hash");

    } catch (const std::invalid_argument& e) {
        LogPrintf("%s\n", e.what());
        memset(&stateRoot, 0, stateRoot.size());
        return stateRoot;
    }

    // --- Step 2: verify account proof ---
    std::vector<unsigned char> accountValue;
    try {
        accountValue = verifyAccountProof();
    } catch (const std::invalid_argument& e) {
        LogPrintf("Account Proof Failed: %s\n", e.what());
        memset(&stateRoot, 0, stateRoot.size());
        return stateRoot;
    }

    // --- Step 3: RLP-encode expected account state and compare with proof value ---
    try {
        std::vector<unsigned char> storageHashVec(storageHash.begin(), storageHash.end());
        std::vector<unsigned char> codeHashVec(codeHash.begin(), codeHash.end());

        std::vector<std::vector<unsigned char>> toEncode = {
            optimizedProof ? uint64ToBEVec(nonce) : ParseHex(uint64_to_hex_deprecated(nonce)),
            GetBalanceAsBEVector(),
            storageHashVec,
            codeHashVec,
        };

        std::vector<unsigned char> encodedAccount = rlp.encode(toEncode);

        // Pad account value to at least 32 bytes.
        while (accountValue.size() < 32)
            accountValue.insert(accountValue.begin(), 0x00);

        if (encodedAccount != accountValue) {
            LogPrintf("ETH Encoded Account does not match proof\n");
            memset(&stateRoot, 0, stateRoot.size());
            return stateRoot;
        }

        LogPrint("crosschain", "%s: PATRICIA Tree proof Account Matches\n", __func__);

    } catch (const std::invalid_argument& e) {
        LogPrintf("RLP Encode failed: %s\n", e.what());
        memset(&stateRoot, 0, stateRoot.size());
        return stateRoot;
    }

    return stateRoot;
}

template<>
bool CETHPATRICIABranch::CheckStorageKeyHash(uint32_t mapIndex) const
{
    // Storage key for a Solidity mapping(K => V) at slot 0:
    //   keccak256(abi.encode(mapIndex, uint256(0)))
    // = keccak256(mapIndex as 32-byte big-endian ++ slot as 32-byte big-endian zeros)
    CKeccack256Writer hw;
    arith_uint256 num256(mapIndex);
    uint256 tmp = ArithToUint256(num256);
    std::vector<unsigned char> mapIndexVec(tmp.begin(), tmp.end());
    std::reverse(mapIndexVec.begin(), mapIndexVec.end()); // to big-endian
    std::vector<unsigned char> slotPadding(32, 0x00);     // slot 0
    mapIndexVec.insert(mapIndexVec.end(), slotPadding.begin(), slotPadding.end());
    hw.write(reinterpret_cast<const char*>(mapIndexVec.data()), mapIndexVec.size());
    return hw.GetHash() == storageProofKey;
}

template<>
uint256 CETHPATRICIABranch::SafeCheck(uint256 hash, bool optimizedProof)
{
    return verifyStorageProof(hash, optimizedProof);
}
