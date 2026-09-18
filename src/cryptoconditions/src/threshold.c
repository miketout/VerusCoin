/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/ThresholdFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"
#include "internal.h"


struct CCType CC_ThresholdType;


static uint32_t thresholdSubtypes(const CC *cond) {
    uint32_t mask = 0;
    for (int i=0; i<cond->size; i++) {
        mask |= cc_typeMask(cond->subconditions[i]);
    }
    mask &= ~(1 << CC_Threshold);
    return mask;
}


static int cmpCostDesc(const void *a, const void *b) {
    return (int) ( *(unsigned long*)b - *(unsigned long*)a );
}


static unsigned long thresholdCost(const CC *cond) {
    CC *sub;
    unsigned long *costs = calloc(1, cond->size * sizeof(unsigned long));
    for (int i=0; i<cond->size; i++) {
        sub = cond->subconditions[i];
        costs[i] = cc_getCost(sub);
    }
    qsort(costs, cond->size, sizeof(unsigned long), cmpCostDesc);
    unsigned long cost = 0;
    for (int i=0; i<cond->threshold; i++) {
        cost += costs[i];
    }
    free(costs);
    return cost + 1024 * cond->size;
}


static int thresholdVisitChildren(CC *cond, CCVisitor visitor) {
    if (cc_isEvalVisitor(&visitor))
    {
        // at this level, we can see whether this node is fulfilled or not. we make that information available to any eval nodes that may
        // get evaluated, so they can determine if they have a reason to fail or not that may depend on signature/fulfillment state
        if (!cc_isFulfilled(cond))
        {
            cc_setEvalVisitorFulfilled(&visitor, 0);
        }
        else
        {
            cc_setEvalVisitorFulfilled(&visitor, 1);
        }
    }
    for (int i=0; i<cond->size; i++) {
        if (!cc_visit(cond->subconditions[i], visitor)) {
            return 0;
        }
    }
    return 1;
}


static int cmpConditionBin(const void *a, const void *b) {
    /* Compare conditions by their ASN binary representation */
    unsigned char bufa[BUF_SIZE], bufb[BUF_SIZE];
    asn_enc_rval_t r0 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)a, bufa, BUF_SIZE);
    asn_enc_rval_t r1 = der_encode_to_buffer(&asn_DEF_Condition, *(Condition_t**)b, bufb, BUF_SIZE);

    // below copied from ASN lib
    size_t commonLen = r0.encoded < r1.encoded ? r0.encoded : r1.encoded;
    int ret = memcmp(bufa, bufb, commonLen);

    if (ret == 0)
        return r0.encoded < r1.encoded ? -1 : 1;
    return 0;
}


static unsigned char *thresholdFingerprint(const CC *cond) {
    /* Create fingerprint */
    ThresholdFingerprintContents_t *fp = calloc(1, sizeof(ThresholdFingerprintContents_t));
    //fprintf(stderr,"thresholdfinger %p\n",fp);
    fp->threshold = cond->threshold;
    for (int i=0; i<cond->size; i++) {
        Condition_t *asnCond = asnConditionNew(cond->subconditions[i]);
        asn_set_add(&fp->subconditions2, asnCond);
    }
    qsort(fp->subconditions2.list.array, cond->size, sizeof(Condition_t*), cmpConditionBin);
    return hashFingerprintContents(&asn_DEF_ThresholdFingerprintContents, fp);
}


static int cmpConditionCost(const void *a, const void *b) {
    CC *ca = *((CC**)a);
    CC *cb = *((CC**)b);

    int out = cc_getCost(ca) - cc_getCost(cb);
    if (out != 0) return out;

    // Do an additional sort to establish consistent order
    // between conditions with the same cost.
    Condition_t *asna = asnConditionNew(ca);
    Condition_t *asnb = asnConditionNew(cb);
    out = cmpConditionBin(&asna, &asnb);
    ASN_STRUCT_FREE(asn_DEF_Condition, asna);
    ASN_STRUCT_FREE(asn_DEF_Condition, asnb);
    return out;
}


static CC *thresholdFromFulfillment(const Fulfillment_t *ffill) {
    ThresholdFulfillment_t *t = ffill->choice.thresholdSha256;
    int threshold = t->subfulfillments.list.count;
    int size = threshold + t->subconditions.list.count;

    CC **subconditions = calloc(size, sizeof(CC*));
    if (!subconditions) {
        return NULL;
    }

    for (int i=0; i<size; i++)
    {
        subconditions[i] = (i < threshold) ?
            fulfillmentToCC(t->subfulfillments.list.array[i]) :
            mkAnon(t->subconditions.list.array[i-threshold]);

        if (!subconditions[i]) {
            for (int j=0; j<i; j++) cc_free(subconditions[j]);
            free(subconditions);
            return 0;
        }
    }

    CC *cond = cc_new(CC_Threshold);
    if (!cond)
    {
        for (int j = 0; j < size; j++)
        {
            cc_free(subconditions[j]);
        }
        free(subconditions);
        return NULL;
    }
    cond->threshold = threshold;
    cond->size = size;
    cond->subconditions = subconditions;
    return cond;
}


static CC *thresholdFromPartialFulfillment(const Fulfillment_t *ffill) {
    ThresholdFulfillment_t *t = ffill->choice.thresholdSha256;
    int size = t->subfulfillments.list.count;
    int threshold = size - t->subconditions.list.count;
    int optimized = 0;

    if (threshold <= 0)
    {
        // more subconditions means that size is subconditions and threshold is difference
        size = t->subconditions.list.count;
        threshold = t->subfulfillments.list.count;
        optimized = 1;
    }

    CC **subconditions = calloc(size, sizeof(CC*));
    if (!subconditions) {
        return NULL;
    }

    if (optimized)
    {
        for (int i=0; i<size; i++)
        {
            subconditions[i] = (i < threshold) ?
                partialFulfillmentToCC(t->subfulfillments.list.array[i]) :
                mkAnon(t->subconditions.list.array[i]);

            if (!subconditions[i]) {
                for (int j=0; j<i; j++) cc_free(subconditions[j]);
                free(subconditions);
                return 0;
            }
        }
    }
    else
    {
        for (int i=0; i < size; i++)
        {
            subconditions[i] = partialFulfillmentToCC(t->subfulfillments.list.array[i]);

            if (!subconditions[i]) {
                for (int j=0; j<i; j++) cc_free(subconditions[j]);
                free(subconditions);
                return 0;
            }
        }
    }

    CC *cond = cc_new(CC_Threshold);
    if (!cond)
    {
        for (int j = 0; j < size; j++)
        {
            cc_free(subconditions[j]);
        }
        free(subconditions);
        return NULL;
    }
    cond->threshold = threshold;
    cond->size = size;
    cond->subconditions = subconditions;
    return cond;
}

int maxThreshholdCountVisit(CC *cond, CCVisitor visitor)
{
    if (cond->type->typeId != CC_Threshold) return 1;
    if (*(int *)visitor.context < cond->threshold)
    {
        *(int *)visitor.context = cond->threshold;
    }
    return 1;
}

static Fulfillment_t *thresholdToPartialFulfillment(const CC *cond) {
    CC *sub;
    Fulfillment_t *fulfillment;

    // Make a copy of subconditions so we can leave original order alone
    CC** subconditions = malloc(cond->size*sizeof(CC*));
    if (!subconditions) {
        return NULL;
    }
    memcpy(subconditions, cond->subconditions, cond->size*sizeof(CC*));
    
    qsort(subconditions, cond->size, sizeof(CC*), cmpConditionCost);

    ThresholdFulfillment_t *tf = calloc(1, sizeof(ThresholdFulfillment_t));

    int needed = cond->threshold;
    int maxSubThresholds = 1;   // maximum required in all nested thresholds, if it is 1, we know that one signature only is required, and we can optimize since waiting for another sig is unnecessary
    CCVisitor subThresholdVisitor = {&maxThreshholdCountVisit, "", 0, &maxSubThresholds};
    thresholdVisitChildren(cond, subThresholdVisitor);
  //  int evalCount = cc_countEvals(cond);
    int canOptimize = 0;

    /*
    // if any sub threshold requires more than one condition, we cannot optimize this, 0 is invalid
    if (maxSubThresholds == 1)
    {
        if (needed == 1 && evalCount == 0)
        {
            canOptimize = 1;
        }
        else if (needed == cond->size)
        {
            // if none will be optimized out and all evals are at the top level, we can optimize if it is satisfied
            int topLevelEvals = 0;
            for (int i = 0; i < cond->size; i++)
            {
                if (cond->type->typeId == CC_Eval)
                    topLevelEvals++;
            }
            if (topLevelEvals == evalCount)
            {
                canOptimize = 1;
            }
        }
    }

    // if we are not fulfilled, do not optimize, this must be done above us if we are not needed
    if (!cc_isFulfilled(cond))
    {
        canOptimize = 0;
    }
    */

    for (int i = 0; i < cond->size; i++)
    {
        sub = subconditions[i];
        int success = 1;

        if (needed)
        {
            fulfillment = asnPartialFulfillmentNew(sub);
            if (fulfillment)
            {
                // optimized has more conditions and fewer partial fulfillments
                if (canOptimize)
                {
                    Condition_t *condNew = asnConditionNew(sub);
                    if (!condNew)
                    {
                        success = 0;
                    }
                    else
                    {
                        asn_set_add(&tf->subconditions, condNew);
                    }
                }
                asn_set_add(&tf->subfulfillments, fulfillment);
                needed--;
            }
            else
            {
                success = 0;
            }
        }
        else if (canOptimize)
        {
            Condition_t *condNew = asnConditionNew(sub);
            if (!condNew)
            {
                success = 0;
            }
            else
            {
                asn_set_add(&tf->subconditions, condNew);
            }
        }
        else
        {
            fulfillment = asnPartialFulfillmentNew(sub);
            Condition_t *condNew = asnConditionNew(sub);
            if (fulfillment && condNew)
            {
                asn_set_add(&tf->subfulfillments, fulfillment);
                asn_set_add(&tf->subconditions, condNew);
            }
            else
            {
                if (fulfillment)
                {
                    asn_set_add(&tf->subfulfillments, fulfillment); // put it here so it will be deleted
                }
                if (condNew)
                {
                    asn_set_add(&tf->subconditions, condNew);
                }
                success = 0;
            }
        }

        if (!success)
        {
            printf("ERROR: cannot decode partial fulfillment\n");
            free(subconditions);
            ASN_STRUCT_FREE(asn_DEF_ThresholdFulfillment, tf);
            return NULL;
        }
    }

    free(subconditions);

    fulfillment = calloc(1, sizeof(Fulfillment_t));
    fulfillment->present = Fulfillment_PR_thresholdSha256;
    fulfillment->choice.thresholdSha256 = tf;
    return fulfillment;
}


static Fulfillment_t *thresholdToFulfillment(const CC *cond) {
    CC *sub;
    Fulfillment_t *fulfillment;

    // Make a copy of subconditions so we can leave original order alone
    CC** subconditions = malloc(cond->size*sizeof(CC*));
    memcpy(subconditions, cond->subconditions, cond->size*sizeof(CC*));
    
    qsort(subconditions, cond->size, sizeof(CC*), cmpConditionCost);

    ThresholdFulfillment_t *tf = calloc(1, sizeof(ThresholdFulfillment_t));

    int needed = cond->threshold;

    for (int i=0; i < cond->size; i++) {
        sub = subconditions[i];
        if (needed && (fulfillment = asnFulfillmentNew(sub)))
        {
            asn_set_add(&tf->subfulfillments, fulfillment);
            needed--;
        }
        else
        {
            asn_set_add(&tf->subconditions, asnConditionNew(sub));
        }
    }

    free(subconditions);

    if (needed) {
        ASN_STRUCT_FREE(asn_DEF_ThresholdFulfillment, tf);
        return NULL;
    }

    fulfillment = calloc(1, sizeof(Fulfillment_t));
    fulfillment->present = Fulfillment_PR_thresholdSha256;
    fulfillment->choice.thresholdSha256 = tf;
    return fulfillment;
}


static CC *thresholdFromJSON(const cJSON *params, char *err) {
    cJSON *threshold_item = cJSON_GetObjectItem(params, "threshold");
    if (!cJSON_IsNumber(threshold_item)) {
        strcpy(err, "threshold must be a number");
        return NULL;
    }

    cJSON *subfulfillments_item = cJSON_GetObjectItem(params, "subfulfillments");
    if (!cJSON_IsArray(subfulfillments_item)) {
        strcpy(err, "subfulfullments must be an array");
        return NULL;
    }

    CC *cond = cc_new(CC_Threshold);
    if (!cond)
    {
        return NULL;
    }
    cond->threshold = (long) threshold_item->valuedouble;
    cond->size = cJSON_GetArraySize(subfulfillments_item);
    cond->subconditions = calloc(cond->size, sizeof(CC*));
    if (!cond->subconditions)
    {
        cc_free(cond);
        return NULL;
    }

    cJSON *sub;
    for (int i=0; i<cond->size; i++) {
        sub = cJSON_GetArrayItem(subfulfillments_item, i);
        cond->subconditions[i] = cc_conditionFromJSON(sub, err);
        if (!cond->subconditions[i])
        {
            cc_free(cond);
            return NULL;
        }
    }

    return cond;
}


static void thresholdToJSON(const CC *cond, cJSON *params) {
    cJSON *subs = cJSON_CreateArray();
    cJSON_AddNumberToObject(params, "threshold", cond->threshold);
    for (int i=0; i<cond->size; i++) {
        cJSON_AddItemToArray(subs, cc_conditionToJSON(cond->subconditions[i]));
    }
    cJSON_AddItemToObject(params, "subfulfillments", subs);
}


static int thresholdIsFulfilled(const CC *cond) {
    int nFulfilled = 0;
    for (int i=0; i<cond->size; i++) {
        if (cc_isFulfilled(cond->subconditions[i])) {
            nFulfilled++;
        }
        if (nFulfilled == cond->threshold) {
            return 1;
        }
    }
    return 0;
}


static void thresholdFree(CC *cond) {
    for (int i=0; i<cond->size; i++) {
        cc_free(cond->subconditions[i]);
    }
    free(cond->subconditions);
}


struct CCType CC_ThresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, &thresholdVisitChildren, &thresholdFingerprint, &thresholdCost, &thresholdSubtypes, &thresholdFromJSON, &thresholdToJSON, &thresholdFromFulfillment, &thresholdToFulfillment, &thresholdFromPartialFulfillment, &thresholdToPartialFulfillment, &thresholdIsFulfilled, &thresholdFree };
