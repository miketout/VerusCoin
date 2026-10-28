/********************************************************************
 * (C) 2026 Michael Toutonghi, largely authored by Claude Fable 5.1
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * This implements tests for the MMR tree functions in the Verus protocol.
 *
 */

#include <boost/test/unit_test.hpp>
#include "mmr.h"
#include "primitives/block.h"
#include "arith_uint256.h"
#include "test/test_bitcoin.h"

BOOST_FIXTURE_TEST_SUITE(mmr_tests, BasicTestingSetup)

// per-block power with distinct work and stake halves, so a wrong sibling or a wrong half shows up
static uint256 BlockPower(uint64_t i)
{
    arith_uint256 work = arith_uint256(1000 + 7 * i);
    arith_uint256 stake = arith_uint256(100 + 3 * i);
    return ArithToUint256((stake << 128) | work);
}

// leaf as the chain builds it (chain.h:547-555): node hash = H(preHash, power); proofs verify against preHash
static uint256 PreHash(uint64_t i)
{
    return uint256S(std::to_string(i));
}

static ChainMMRNode Leaf(uint64_t i)
{
    uint256 power = BlockPower(i);
    return ChainMMRNode(ChainMMRNode::HashObj(PreHash(i), power), power);
}

BOOST_AUTO_TEST_CASE(prefix_power_matches_running_sum)
{
    typedef CMerkleMountainRange<ChainMMRNode, CChunkedLayer<ChainMMRNode, 2>> PowerMMR;
    typedef CMerkleMountainView<ChainMMRNode, CChunkedLayer<ChainMMRNode, 2>> PowerMMV;

    const uint64_t maxLeaves = 70;
    PowerMMR mmr;
    std::vector<arith_uint256> runningSum;
    arith_uint256 total = 0;

    for (uint64_t i = 0; i < maxLeaves; i++)
    {
        uint256 power = BlockPower(i);
        total += UintToArith256(power);
        runningSum.push_back(total);
        mmr.Add(Leaf(i));

        // every view size from 1 leaf up: proves each leaf against the current root
        PowerMMV view(mmr);
        BOOST_CHECK_EQUAL(view.size(), i + 1);
        uint256 root = view.GetRoot();

        for (uint64_t pos = 0; pos <= i; pos++)
        {
            CMMRProof proof;
            BOOST_REQUIRE(view.GetProof(proof, pos));
            BOOST_REQUIRE_EQUAL(proof.proofSequence.size(), (size_t)1);
            BOOST_REQUIRE(proof.proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE);

            // the proof still verifies to the root
            BOOST_CHECK(proof.CheckProof(PreHash(pos)) == root);

            const CMMRPowerNodeBranch &branch = *(CMMRPowerNodeBranch *)proof.proofSequence[0];
            BOOST_CHECK(UintToArith256(branch.GetPrefixPower()) == runningSum[pos]);   // cumulative through pos
            BOOST_CHECK(branch.branch.size() >= 1 && branch.branch[0] == BlockPower(pos)); // leaf power
            BOOST_CHECK(UintToArith256(branch.branch.back()) == total);               // root power
        }
    }
}

// a tampered parent power must change the prefix
BOOST_AUTO_TEST_CASE(prefix_power_tamper)
{
    typedef CMerkleMountainRange<ChainMMRNode, CChunkedLayer<ChainMMRNode, 2>> PowerMMR;
    typedef CMerkleMountainView<ChainMMRNode, CChunkedLayer<ChainMMRNode, 2>> PowerMMV;

    PowerMMR mmr;
    for (uint64_t i = 0; i < 13; i++)
    {
        mmr.Add(Leaf(i));
    }
    PowerMMV view(mmr);
    uint256 root = view.GetRoot();

    CMMRProof proof;
    BOOST_REQUIRE(view.GetProof(proof, 9));           // 9 is a right child at level 0 and inside a non-final peak
    CMMRPowerNodeBranch branch = *(CMMRPowerNodeBranch *)proof.proofSequence[0];
    uint256 good = branch.GetPrefixPower();

    // bump one parent power by one unit of work
    branch.branch[2] = ArithToUint256(UintToArith256(branch.branch[2]) + 1);
    BOOST_CHECK(branch.GetPrefixPower() != good);
    BOOST_CHECK(branch.SafeCheck(PreHash(9)) != root);
}

// GetProof must select the peak by height: a one-leaf peak equal in hash to the first peak still proves everywhere
BOOST_AUTO_TEST_CASE(duplicate_peak_hash_proof)
{
    typedef CMerkleMountainRange<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>> HashMMR;
    typedef CMerkleMountainView<CDefaultMMRNode, CChunkedLayer<CDefaultMMRNode, 2>> HashMMV;

    // 4+2+1, 8+2+1, 8+4+1, 8+4+2+1 leaves: the final peak is one leaf, and there are three or four peaks
    for (uint64_t n : {7, 11, 13, 15})
    {
        HashMMR mmr;
        for (uint64_t i = 0; i + 1 < n; i++)
        {
            mmr.Add(CDefaultMMRNode(uint256S(std::to_string(i + 1))));
        }

        // the tallest peak has height floor(log2(n)); make the final one-leaf peak its exact hash
        uint32_t topHeight = 0;
        while ((n >> (topHeight + 1)) != 0)
        {
            topHeight++;
        }
        uint256 repeated = mmr.GetNode(topHeight, 0).hash;
        mmr.Add(CDefaultMMRNode(repeated));

        HashMMV view(mmr);
        BOOST_REQUIRE_EQUAL(view.size(), n);
        uint256 root = view.GetRoot();

        for (uint64_t pos = 0; pos < n; pos++)
        {
            CMMRProof proof;
            BOOST_REQUIRE(view.GetProof(proof, pos));
            BOOST_REQUIRE_EQUAL(proof.proofSequence.size(), (size_t)1);
            BOOST_REQUIRE(proof.proofSequence[0]->branchType == CMerkleBranchBase::BRANCH_MMRBLAKE_NODE);

            uint256 leaf = (pos + 1 == n) ? repeated : uint256S(std::to_string(pos + 1));
            BOOST_CHECK_MESSAGE(proof.CheckProof(leaf) == root, "n=" << n << " pos=" << pos);
        }

        // the duplicate leaf is its own peak: its branch holds one sibling per peak-merkle layer it is hashed in,
        // nothing from inside the tall peak (one sibling with three peaks, two with four)
        CMMRProof last;
        BOOST_REQUIRE(view.GetProof(last, n - 1));
        const CMMRNodeBranch &branch = *(CMMRNodeBranch *)last.proofSequence[0];
        BOOST_CHECK_EQUAL(branch.branch.size(), view.GetPeaks().size() == 3 ? (size_t)1 : (size_t)2);
    }
}

BOOST_AUTO_TEST_SUITE_END()
