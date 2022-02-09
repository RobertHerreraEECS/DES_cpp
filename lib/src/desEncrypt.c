#ifdef __cplusplus
extern "C"
{
#endif

//TODO: finish the ports for BSD and windows based platforms

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "permTables.h"
#include "desEncrypt.h"

#if defined(_WIN32) || defined(_WIN64)

#elif defined (__linux__)
#include <byteswap.h>
#elif defined (__MACH__) || defined (__unix__)

#endif

void dumphex(char *data, int size) {
    int i;
    int row = 8;
    for(i = 0; i < size; i++) {
        printf("%02x", (uint8_t) data[i]);
        if (i % row == 0 && i != 0)
        printf("\n");
    }
    printf("\n");
}

CryptAPI initialize(DESCtx *ctx) {
    size_t numBlocks, padding = 0,i = 0;

    memset(ctx->subkeys, 0, sizeof(uint64_t) * NUM_SUB_KEYS);

    if (ctx->inSize == 0) {
        printf("Specify a message size within the context.\n");
        return CRYPT_INPUT_ERROR;
    }

    numBlocks = (ctx->inSize / 8);
    numBlocks += 1;

    padding = (8 - (ctx->inSize % 8));
    ctx->blocks = numBlocks;
    ctx->outSize = 8 * numBlocks;

    ctx->out = (char *) calloc(1, ctx->outSize);

    if (ctx->pad == PKCS5Pad) {
        for (i = 0; i < padding; i++) {
            ctx->out[ctx->inSize + i] = padding;
        }
    }

    CRYPT_MEMCPY(ctx->out, ctx->in, ctx->inSize);

    generateKeySchedule(*((uint64_t *) ctx->key), ctx->subkeys);
    return CRYPT_SUCCESS;
}

CryptAPI finalize(DESCtx *ctx, CtxType type) {
    bool cryptType = false;
    CryptAPI ret;
   
    if (ctx->op == UNK_Mode) {
        printf("Specify a mode of operation.\n");
        return CRYPT_INPUT_ERROR;
    }

    if (type == DecryptT)
        cryptType = true;

    if (ctx->op == ECB_Mode) 
    ret = encryptBlocksECB(ctx, cryptType);

    if (ctx->op == CBC_Mode) 
    ret = encryptBlocksCBC(ctx, cryptType);

    if (ctx->op == CFB_Mode) 
    ret = encryptBlocksCFB(ctx, cryptType);

    if (ctx->op == OFB_Mode) 
    ret = encryptBlocksOFB(ctx, cryptType);

    return ret;
}

CryptAPI encryptBlocksECB(DESCtx *ctx, bool cryptType) {
    int i = 0;
    uint64_t *dataPtr = NULL;


    dataPtr = (uint64_t *) (ctx->out);
    for (i = 0; i < ctx->blocks; i++) {

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        CryptDES(dataPtr, ctx->subkeys, cryptType);

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        dataPtr++;
    }
    return CRYPT_SUCCESS;
}

CryptAPI encryptBlocksCBC(DESCtx *ctx, bool cryptType) {
    int i = 0;
    uint64_t *dataPtr = NULL;
    uint64_t *chainData = NULL;

    *(uint64_t *) ctx->iv = 0;

    dataPtr = (uint64_t *) (ctx->out);
    for (i = 0; i < ctx->blocks; i++) {

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        if (i == 0)
        chainData = (uint64_t *) ctx->iv;

        *dataPtr ^= *chainData;
        CryptDES(dataPtr, ctx->subkeys, cryptType);
        *chainData = *dataPtr;

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        dataPtr++;
    }

    return CRYPT_SUCCESS;
}

CryptAPI encryptBlocksCFB(DESCtx *ctx, bool cryptType) {
    int i = 0;
    uint64_t *dataPtr = NULL;
    uint64_t *chainData = NULL;

    *(uint64_t *) ctx->iv = 0;

    dataPtr = (uint64_t *) (ctx->out);
    for (i = 0; i < ctx->blocks; i++) {

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        if (i == 0)
        chainData = (uint64_t *) ctx->iv;

        CryptDES(chainData, ctx->subkeys, cryptType);

        *dataPtr ^= *chainData;

        *chainData = *dataPtr;

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        dataPtr++;
    }

    return CRYPT_SUCCESS;
}

CryptAPI encryptBlocksOFB(DESCtx *ctx, bool cryptType) {
    int i = 0;
    uint64_t *dataPtr = NULL;
    uint64_t *chainData = NULL;

    *(uint64_t *) ctx->iv = 0;

    dataPtr = (uint64_t *) (ctx->out);
    for (i = 0; i < ctx->blocks; i++) {

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        if (i == 0)
        chainData = (uint64_t *) ctx->iv;

        CryptDES(chainData, ctx->subkeys, cryptType);

        *dataPtr ^= *chainData;

        #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #if defined(_WIN32) || defined(_WIN64)
        *dataPtr = _byteswap_uint64(*dataPtr);
        #elif defined (__linux__)
        *dataPtr = bswap_64(*dataPtr);
        #elif defined (__MACH__) || defined (__unix__)
        *dataPtr = __builtin_bswap64(*dataPtr);
        #endif
        #endif

        dataPtr++;
    }

    return CRYPT_SUCCESS;
}

void sanitize(DESCtx *ctx) {
    if (ctx->out != NULL) {
        memset(ctx->out, 0, ctx->outSize);
        free(ctx->out);
    } else { return; }
    memset(ctx, 0, sizeof(DESCtx));
    free(ctx);
}

void CryptDES(uint64_t *message,uint64_t *subkeys, bool decrypt) {
    int i,j,k;
    uint64_t _ip = 0;
    uint64_t finalPermutation = 0;
    uint64_t concatBlocks = 0;
    uint32_t r[NUM_BLOCKS + 1] = {0};
    uint32_t l[NUM_BLOCKS + 1] = {0};


    // encode with intial permutation
    for (i = 0; i < INT_SIZE64; i++) {
        _ip |= (uint64_t) (((*message >> (uint64_t) (MAX_SIZE - IP[i]) ) & 0x1) << (MAX_SIZE - 1 - i));
    }

    // split permutated message into
    // right and left blocks
    r[0] |= _ip;
    l[0] = _ip >> ((INT_SIZE64) / 2);

    // rounds
    if (!decrypt) {
        for (i = 1; i <= NUM_BLOCKS; i++) {
    	    l[i] = r[i-1];
    	    r[i] = l[i-1] ^ sBoxPermutation(r[i-1],subkeys[i-1]);
        }
    } else {
        for (i = 1; i <= NUM_BLOCKS; i++) {
    	    l[i] = r[i-1];
    	    r[i] = l[i-1] ^ sBoxPermutation(r[i-1],subkeys[NUM_SUB_KEYS -  i]);
    	}
    }

    concatBlocks |= r[16];
    concatBlocks = concatBlocks << ((INT_SIZE64) / 2);
    concatBlocks |= l[16];

    // final inverse permutation
    for (j = 0; j < INT_SIZE64; j++)
    finalPermutation |= ((concatBlocks >>  ((uint64_t) INT_SIZE64 - FP[j])) & 0x1) << (uint64_t)(INT_SIZE64 - 1 - j);
    *message = finalPermutation;
}

void generateKeySchedule(const uint64_t key, uint64_t *subKeys) {
    
    int i,j;
    uint64_t key_plus = 0;
    uint32_t _c[NUM_SUB_KEYS+1] = {0};
    uint32_t _d[NUM_SUB_KEYS+1] = {0};
    uint64_t _cd[NUM_SUB_KEYS] = {0};
    uint32_t temp = 0;
    int shiftSchedule[NUM_SUB_KEYS] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    //load key in big endian and perform PC-1
    for (i = 0; i < INT_SIZE56; i++) {
		key_plus |= (uint64_t) (((key >> (uint64_t) (MAX_SIZE - PC1[i]) ) & 0x1) << (MAX_SIZE - 1 - i));
	}

    // seperate permutation into c and d blocks
    _c[0] = (key_plus>>36);
    _d[0] = (key_plus>>8);

    for (i = 1; i < NUM_SUB_KEYS + 1; i++) {
    
        temp = _d[i-1];
        for (j = 1; j <= shiftSchedule[i-1]; j++) {
            _d[i] = (temp << 1) | (1 & (temp >> 27));
            temp = _d[i];
        }

        temp = _c[i-1];
        for (j = 1; j <= shiftSchedule[i-1]; j++) {
            _c[i] = (temp << 1) | (1 & (temp >> 27));
            temp = _c[i];
        }

        // clear high bits
        _c[i] = (_c[i] << 4) >> 4;
        _d[i] = (_d[i] << 4) >> 4;
    } 

    // concatenate blocks
    for (i = 0; i < NUM_SUB_KEYS; i++) {
        _cd[i] |= _c[i+1];
        _cd[i] = (_cd[i] << 28);
        _cd[i] |= _d[i+1];
    }

    // generate key schedule
    for (i = 0; i < NUM_SUB_KEYS; i++) {
        for (j = 0; j < (INT_SIZE48); j++)
	    subKeys[i] |= (_cd[i] >> ((INT_SIZE56) - PC2[j]) & 0x1) << ((INT_SIZE48) - j - 1);
    }
}

uint32_t sBoxPermutation (const uint32_t block, uint64_t key) {
    uint64_t _e = 0;
    uint32_t pOut = 0;
    uint32_t sLookup;
    int j, index, count = 0, sBoxCount = 0;
    uint8_t sCmpn, row = 0, column = 0;

    // expand right block (E)
    for (j = 0; j < INT_SIZE48; j++)
    _e |= (((uint64_t) (block >>  ((INT_SIZE32) - E[j])) & 0x1) << ((INT_SIZE48) - j - 1));

    // sBox Lookup table
    count = INT_SIZE48;
    sBoxCount = 1;
    sLookup = 0;
    while (count != 0) {

        count -= 6;

        // extract 6 bits at a time from output of e ^ K
        sCmpn = (((_e ^ key) >> (count)) << 2) >> 2;
        row = (((sCmpn >> 5) & 1) << 1) | (sCmpn & 1);
        column = (sCmpn >> 1) & 0xf;

        index = (NUM_BLOCKS*row + column);

        sLookup |= SBOXMAP[sBoxCount - 1][index];
        if (sBoxCount != 8) sLookup <<= 4; 
        sBoxCount++;
    }

    // sBox Permutation
    for (j = 0; j < INT_SIZE32; j++)
        pOut |= ((sLookup >>  (uint32_t) ((INT_SIZE32) - P[j])) & 0x1)  << (uint32_t)((INT_SIZE32) - 1 -j);
    return pOut;
}

#ifdef __cplusplus
}
#endif
