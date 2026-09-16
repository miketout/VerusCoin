#define _GNU_SOURCE 1

#if __linux
#include <sys/syscall.h>
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h> 
#endif

#include <unistd.h>
#include <pthread.h>

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Secp256k1Fulfillment.h"
#include "asn/Secp256k1FingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "include/sha256.h"
#include "include/ripemd-160.h"
#include "include/secp256k1/include/secp256k1.h"
#include "cryptoconditions.h"
#include "internal.h"


struct CCType CC_Secp256k1Type;


static const size_t SECP256K1_PK_SIZE = 33;
static const size_t SECP256K1_SK_SIZE = 32;
static const size_t SECP256K1_SIG_SIZE = 64;


secp256k1_context *ec_ctx_sign = 0, *ec_ctx_verify = 0;
pthread_mutex_t cc_secp256k1ContextLock = PTHREAD_MUTEX_INITIALIZER;


void lockSign() {
    pthread_mutex_lock(&cc_secp256k1ContextLock);
    if (!ec_ctx_sign) {
        ec_ctx_sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    }
    unsigned char ent[32];
#ifdef SYS_getrandom
    int read = syscall(SYS_getrandom, ent, 32, 0);
#else
    FILE *fp = fopen("/dev/urandom", "r");
    int read = (int) fread(&ent, 1, 32, fp);
    fclose(fp);
#endif
    if (read != 32)
    {
        int32_t i;
        for (i=0; i<32; i++)
            ((uint8_t *)ent)[i] = rand();
    }
    if (!secp256k1_context_randomize(ec_ctx_sign, ent)) {
        fprintf(stderr, "Could not randomize secp256k1 context\n");
        exit(1);
    }
}


void unlockSign() {
    pthread_mutex_unlock(&cc_secp256k1ContextLock);
}


void initVerify() {
    if (!ec_ctx_verify) {
        pthread_mutex_lock(&cc_secp256k1ContextLock);
        if (!ec_ctx_verify)
            ec_ctx_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        pthread_mutex_unlock(&cc_secp256k1ContextLock);
    }
}


static unsigned char *secp256k1Fingerprint(const CC *cond) {
    Secp256k1FingerprintContents_t *fp = calloc(1, sizeof(Secp256k1FingerprintContents_t));
    //fprintf(stderr,"secpfinger %p %p size %d vs %d\n",fp,cond->publicKey,(int32_t)sizeof(Secp256k1FingerprintContents_t),(int32_t)SECP256K1_PK_SIZE);
    OCTET_STRING_fromBuf(&fp->publicKey, cond->publicKey, SECP256K1_PK_SIZE);
    return hashFingerprintContents(&asn_DEF_Secp256k1FingerprintContents, fp);
}


static bool cc_secp256k1IsPKHash(const unsigned char *publicKey)
{
    if (!publicKey)
    {
        return 0;
    }

    assert(SECP256K1_PK_SIZE == 33);
    static uint8_t zcheck[33] = {0};

    // not all zero in first 20, all zero from that to the end means we assume this is a hash and carries the public key with the signature
    if (memcmp(publicKey, zcheck, 20) && !memcmp(publicKey + 20, zcheck + 20, SECP256K1_PK_SIZE - 20))
    {
        return 1;
    }
    return 0;
}


int secp256k1Verify(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != CC_Secp256k1Type.typeId) return 1;

    // isfulfilled should pass, and since the existing signatures that allow it to pass that are
    // properly validated below, this is safe
    if (!cond->signature)
    {
        return 1;
    }

    initVerify();

    int rc;

    // parse pubkey
    secp256k1_pubkey pk;

    if (cc_secp256k1IsPKHash(cond->publicKey))
    {
        bool pkHashMatch = 0;
        unsigned char *shaHash = calloc(1,32);
        unsigned char *ripemdHash = calloc(1, 20);

        sha256(cond->signature + SECP256K1_SIG_SIZE, SECP256K1_PK_SIZE, shaHash);
        hash160(shaHash, 32, ripemdHash);
        
        // if hash is not a hash of the public key, return false
        if (!memcmp(cond->publicKey, ripemdHash, 20))
        {
            pkHashMatch = 1;
        }

        free(ripemdHash);
        free(shaHash);

        if (!pkHashMatch)
        {
            return 0;
        }
        rc = secp256k1_ec_pubkey_parse(ec_ctx_verify, &pk, cond->signature + SECP256K1_SIG_SIZE, SECP256K1_PK_SIZE);
    }
    else
    {
        rc = secp256k1_ec_pubkey_parse(ec_ctx_verify, &pk, cond->publicKey, SECP256K1_PK_SIZE);
    }

    if (rc != 1) return 0;

    // parse signature
    secp256k1_ecdsa_signature sig;
    rc = secp256k1_ecdsa_signature_parse_compact(ec_ctx_verify, &sig, cond->signature);
    if (rc != 1) return 0;

    // Only accepts lower S signatures
    rc = secp256k1_ecdsa_verify(ec_ctx_verify, &sig, visitor.msg, &pk);
    if (rc != 1) return 0;

    return 1;
}


int cc_secp256k1VerifyTreeMsg32(const CC *cond, const unsigned char *msg32) {
    int subtypes = cc_typeMask(cond);
    if (subtypes & (1 << CC_PrefixType.typeId) &&
        subtypes & (1 << CC_Secp256k1Type.typeId)) {
        // No support for prefix currently, due to pending protocol decision on
        // how to combine message and prefix into 32 byte hash
        return 0;
    }
    CCVisitor visitor = {&secp256k1Verify, msg32, 0, NULL};
    int out = cc_visit(cond, visitor);
    return out;
}


/*
 * Signing data
 */
typedef struct CCSecp256k1SigningData {
    const unsigned char *pk;
    const unsigned char *sk;
    int nSigned;
} CCSecp256k1SigningData;


/*
 * sign a message with a private key
 */
int cc_MakeSecp256k1Signature(const unsigned char *msg32, const unsigned char *privateKey, unsigned char **signatureOut) {
    secp256k1_ecdsa_signature sig;
    lockSign();
    int rc = secp256k1_ecdsa_sign(ec_ctx_sign, &sig, msg32, privateKey, NULL, NULL);
    unlockSign();

    if (rc != 1) return 0;

    *signatureOut = calloc(1, SECP256K1_SIG_SIZE);
    secp256k1_ecdsa_signature_serialize_compact(ec_ctx_verify, *signatureOut, &sig);
    return 1;
}


/*
 * Visitor that signs an secp256k1 condition if it has a matching public key
 */
static int secp256k1Sign(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != CC_Secp256k1) return 1;
    CCSecp256k1SigningData *signing = (CCSecp256k1SigningData*) visitor.context;

    bool pkHashMatch = 0;

    /*
    char *jsonCondStr = cc_conditionToJSONString(cond);
    if (jsonCondStr)
    {
        printf("Ready to sign condition: %s\n", jsonCondStr);
        cJSON_free(jsonCondStr);
    }
    */

    // if we don't match, check if it is a pkhash
    if (memcmp(cond->publicKey, signing->pk, SECP256K1_PK_SIZE))
    {
        // no hash match if not a possible hash
        if (!cc_secp256k1IsPKHash(cond->publicKey))
        {
            return 1;
        }

        // we will sign a node if either the keys match, or the node holds a KeyID of the public key followed by zeros, which is a sha256+ripemd hash of the contents
        unsigned char *shaHash = calloc(1,32);
        unsigned char *ripemdHash = calloc(1, 20);

        sha256(signing->pk, SECP256K1_PK_SIZE, shaHash);
        hash160(shaHash, 32, ripemdHash);
        pkHashMatch = !memcmp(cond->publicKey, ripemdHash, 20);

        free(ripemdHash);
        free(shaHash);

        if (!pkHashMatch)
        {
            return 1;
        }
    }

    secp256k1_ecdsa_signature sig;
    lockSign();
    int rc = secp256k1_ecdsa_sign(ec_ctx_sign, &sig, visitor.msg, signing->sk, NULL, NULL);
    unlockSign();

    if (rc != 1) return 0;

    if (pkHashMatch)
    {
        if (!cond->signature) cond->signature = calloc(1, SECP256K1_SIG_SIZE + SECP256K1_PK_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ec_ctx_verify, cond->signature, &sig);
        memcpy(cond->signature + SECP256K1_SIG_SIZE, signing->pk, SECP256K1_PK_SIZE);
    }
    else
    {
        if (!cond->signature) cond->signature = calloc(1, SECP256K1_SIG_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ec_ctx_verify, cond->signature, &sig);
    }

    signing->nSigned++;
    return 1;
}


struct SecP256k1ApplyData {
    const unsigned char *publicKey;
    const unsigned char *pubkeyHash20;
    const unsigned char *signature;
    unsigned int applyCount;
};


/*
 * put a copy of the signature on this node if it can accept it
 */
static int secp256k1Apply(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != CC_Secp256k1) return 1;
    struct SecP256k1ApplyData *apply = (struct SecP256k1ApplyData *)visitor.context;

    /*
    char *jsonCondStr = cc_conditionToJSONString(cond);
    if (jsonCondStr)
    {
        printf("Ready to apply sig: %s\n", jsonCondStr);
        cJSON_free(jsonCondStr);
    }
    */

    // if we match, add or replace the signature, if the signature is null, remove the signature
    int isPKHash = 0;
    if (!memcmp(cond->publicKey, apply->publicKey, SECP256K1_PK_SIZE) || ((isPKHash = cc_secp256k1IsPKHash(cond->publicKey)) && !memcmp(cond->publicKey, apply->pubkeyHash20, 20)))
    {
        if (cond->signature)
        {
            free(cond->signature);
        }
        if (apply->signature)
        {
            cond->signature = calloc(1, isPKHash ? (SECP256K1_SIG_SIZE + SECP256K1_PK_SIZE) : SECP256K1_SIG_SIZE);
            memcpy(cond->signature, apply->signature, SECP256K1_SIG_SIZE);
            if (isPKHash)
            {
                memcpy(cond->signature + SECP256K1_SIG_SIZE, apply->publicKey, SECP256K1_PK_SIZE);
            }
        }
        else
        {
            cond->signature = NULL;
        }
    }
    else
    {
        return 1;
    }

    /*
    jsonCondStr = cc_conditionToJSONString(cond);
    if (jsonCondStr)
    {
        printf("After signature: %s\n", jsonCondStr);
        cJSON_free(jsonCondStr);
    }
    */

    apply->applyCount++;
    return 1;
}


/*
 * sign a message with a private key, return true if the signature was accepted by at least one node
 */
int cc_ApplySecp256k1Signature(const CC *cond, const unsigned char *publicKey, const unsigned char *pubkeyHash20, const unsigned char *signature) {
    struct SecP256k1ApplyData ad = {publicKey, pubkeyHash20, signature, 0}; 
    CCVisitor visitor = {&secp256k1Apply, "", 0, &ad};
    cc_visit(cond, visitor);
    return ad.applyCount != 0;
}


/*
 * Sign secp256k1 conditions in a tree
 */
int cc_signTreeSecp256k1Msg32(CC *cond, const unsigned char *privateKey, const unsigned char *msg32) {
    if (cc_typeMask(cond) & (1 << CC_Prefix)) {
        // No support for prefix currently, due to pending protocol decision on
        // how to combine message and prefix into 32 byte hash
        return 0;
    }

    // derive the pubkey
    secp256k1_pubkey spk;
    lockSign();
    int rc = secp256k1_ec_pubkey_create(ec_ctx_sign, &spk, privateKey);
    unlockSign();
    if (rc != 1) {
        fprintf(stderr, "Cryptoconditions couldn't derive secp256k1 pubkey\n");
        return 0;
    }

    // serialize pubkey
    unsigned char *publicKey = calloc(1, SECP256K1_PK_SIZE);
    size_t ol = SECP256K1_PK_SIZE;
    secp256k1_ec_pubkey_serialize(ec_ctx_verify, publicKey, &ol, &spk, SECP256K1_EC_COMPRESSED);

    // sign
    CCSecp256k1SigningData signing = {publicKey, privateKey, 0};

    /*
    char *jsonCondStr = cc_conditionToJSONString(cond);
    if (jsonCondStr)
    {
        printf("Ready to sign condition: %s\nusing privkey with pubkey: ", jsonCondStr);
        for (int i = 0; i < SECP256K1_PK_SIZE; i++)
        {
            printf("%02X", *(signing.pk + i));
        }
        printf("\nand a pkhash value of: ");
        // we will sign a node if either the keys match, or the node holds a KeyID of the public key followed by zeros, which is a sha256+ripemd hash of the contents
        unsigned char *shaHash = calloc(1,32);
        unsigned char *ripemdHash = calloc(1, 20);

        sha256(signing.pk, SECP256K1_PK_SIZE, shaHash);
        hash160(shaHash, 32, ripemdHash);
        for (int i = 0; i < 20; i++)
        {
            printf("%02X", *(ripemdHash + i));
        }
        printf("\n");

        free(shaHash);
        free(ripemdHash);

        cJSON_free(jsonCondStr);
    }
    */

    CCVisitor visitor = {&secp256k1Sign, msg32, 32, &signing};
    cc_visit(cond, visitor);

    free(publicKey);
    return signing.nSigned;
}


static unsigned long secp256k1Cost(const CC *cond) {
    return 131072;
}


static CC *cc_secp256k1Condition(const unsigned char *publicKey, const unsigned char *signature,
                                 size_t signatureLen) {
    // Check that pk parses
    initVerify();
    secp256k1_pubkey spk;
    int rc = secp256k1_ec_pubkey_parse(ec_ctx_verify, &spk, publicKey, SECP256K1_PK_SIZE);

    int signatureSize = SECP256K1_SIG_SIZE;

    if (!rc) {
        // not all zero in first 20, all zero from that to the end means we assume this is a hash and carries the public key with the signature
        if (cc_secp256k1IsPKHash(publicKey))
        {
            signatureSize += SECP256K1_PK_SIZE;
        }
        else
        {
            return NULL;
        }
    }

    if (signature && signatureLen != (size_t)signatureSize)
    {
        return NULL;
    }

    unsigned char *pk = 0, *sig = 0;

    pk = calloc(1, SECP256K1_PK_SIZE);
    if (pk)
    {
        memcpy(pk, publicKey, SECP256K1_PK_SIZE);
        if (signature) {
            sig = calloc(1, signatureSize);
            if (!sig)
            {
                free(pk);
                return NULL;
            }
            memcpy(sig, signature, signatureSize);
        }
    }
    else
    {
        return NULL;
    }

    CC *cond = cc_new(CC_Secp256k1);
    if (!cond)
    {
        free(sig);
        free(pk);
        return NULL;
    }
    cond->publicKey = pk;
    cond->signature = sig;
    return cond;
}


static CC *secp256k1FromJSON(const cJSON *params, char *err) {
    CC *cond = 0;
    unsigned char *pk = 0, *sig = 0;
    size_t pkSize = 0, sigSize = 0;

    if (!jsonGetHex(params, "publicKey", err, &pk, &pkSize)) goto END;

    if (pkSize != SECP256K1_PK_SIZE) { strcpy(err, "publicKey has incorrect length"); goto END; }

    if (!jsonGetHexOptional(params, "signature", err, &sig, &sigSize)) goto END;

    if (sig)
    {
        bool isPKHash = cc_secp256k1IsPKHash(pk);

        if ((!isPKHash && SECP256K1_SIG_SIZE != sigSize) || (isPKHash && (SECP256K1_SIG_SIZE + SECP256K1_PK_SIZE) != sigSize)) {
            strcpy(err, "signature has incorrect length");
            goto END;
        }
    }

    cond = cc_secp256k1Condition(pk, sig, sigSize);
    if (!cond) {
        strcpy(err, "invalid public key");
    }
END:
    free(pk);
    free(sig);
    return cond;
}


static void secp256k1ToJSON(const CC *cond, cJSON *params) {
    jsonAddHex(params, "publicKey", cond->publicKey, SECP256K1_PK_SIZE);
    if (cond->signature) {
        int sigSize = SECP256K1_SIG_SIZE;
        if (cc_secp256k1IsPKHash(cond->publicKey))
        {
            sigSize += SECP256K1_PK_SIZE;
        }
        jsonAddHex(params, "signature", cond->signature, sigSize);
    }
}


static CC *secp256k1FromFulfillment(const Fulfillment_t *ffill) {
    if (ffill->choice.secp256k1Sha256.publicKey.size != SECP256K1_PK_SIZE) {
        return NULL;
    }
    return cc_secp256k1Condition(ffill->choice.secp256k1Sha256.publicKey.buf,
                                 ffill->choice.secp256k1Sha256.signature.buf,
                                 ffill->choice.secp256k1Sha256.signature.size);
}


static Fulfillment_t *secp256k1ToFulfillment(const CC *cond) {
    if (!cond->signature) {
        return NULL;
    }

    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_secp256k1Sha256;
    Secp256k1Fulfillment_t *sec = &ffill->choice.secp256k1Sha256;

    OCTET_STRING_fromBuf(&sec->publicKey, cond->publicKey, SECP256K1_PK_SIZE);

    // not all zero in first 20, all zero from that to the end means we assume this is a hash and carries the public key with the signature
    if (cc_secp256k1IsPKHash(cond->publicKey))
    {
        OCTET_STRING_fromBuf(&sec->signature, cond->signature, SECP256K1_SIG_SIZE + SECP256K1_PK_SIZE);
    }
    else
    {
        OCTET_STRING_fromBuf(&sec->signature, cond->signature, SECP256K1_SIG_SIZE);
    }
    return ffill;
}


static CC *secp256k1FromPartialFulfillment(const Fulfillment_t *ffill) {
    if (ffill->choice.secp256k1Sha256.publicKey.size != SECP256K1_PK_SIZE) {
        return NULL;
    }
    return cc_secp256k1Condition(ffill->choice.secp256k1Sha256.publicKey.buf,
                                 ffill->choice.secp256k1Sha256.signature.size == 0 ? NULL : ffill->choice.secp256k1Sha256.signature.buf,
                                 ffill->choice.secp256k1Sha256.signature.size);
}


static Fulfillment_t *secp256k1ToPartialFulfillment(const CC *cond) {
    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_secp256k1Sha256;
    Secp256k1Fulfillment_t *sec = &ffill->choice.secp256k1Sha256;

    OCTET_STRING_fromBuf(&sec->publicKey, cond->publicKey, SECP256K1_PK_SIZE);

    if (cond->signature)
    {
        // not all zero in first 20, all zero from that to the end means we assume this is a hash and carries the public key with the signature
        if (cc_secp256k1IsPKHash(cond->publicKey))
        {
            OCTET_STRING_fromBuf(&sec->signature, cond->signature, SECP256K1_SIG_SIZE + SECP256K1_PK_SIZE);
        }
        else
        {
            OCTET_STRING_fromBuf(&sec->signature, cond->signature, SECP256K1_SIG_SIZE);
        }
    }
    else
    {
        sec->signature.buf = NULL;
        sec->signature.size = 0;
    }
    
    return ffill;
}


int secp256k1IsFulfilled(const CC *cond) {
    return cond->signature != 0;
}


static void secp256k1Free(CC *cond) {
    free(cond->publicKey);
    if (cond->signature) {
        free(cond->signature);
    }
}


static uint32_t secp256k1Subtypes(const CC *cond) {
    return 0;
}


struct CCType CC_Secp256k1Type = { 5, "secp256k1-sha-256", Condition_PR_secp256k1Sha256, 0, &secp256k1Fingerprint, &secp256k1Cost, &secp256k1Subtypes, &secp256k1FromJSON, &secp256k1ToJSON, &secp256k1FromFulfillment, &secp256k1ToFulfillment, &secp256k1FromPartialFulfillment, &secp256k1ToPartialFulfillment, &secp256k1IsFulfilled, &secp256k1Free };
