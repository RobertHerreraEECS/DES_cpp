#ifndef DES_ENCRYPT_H
#define DES_ENCRYPT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <inttypes.h>
#include <string.h>


#define MAX_SIZE sizeof(uint64_t) * 8
#define INT_SIZE64 sizeof(uint64_t) * 8
#define INT_SIZE56 sizeof(uint64_t) * 7
#define INT_SIZE48 sizeof(uint64_t) * 6
#define INT_SIZE32 sizeof(uint64_t) * 4
#define NUM_BLOCKS 16
#define NUM_SUB_KEYS 16
#define KEY_BYTES 8

#define MEMCLEAR(s, c, n) memset((s), (c), (n))
#define CRYPT_MEMCPY(dest, src, n) memcpy((dest), (src), (n))

/**
* @brief Populating this context is recommeded
* when encrypting/decrypting. It allows the
* all cipher metadata to located in one place
* for easy sanitization.
*
* The CryptDES function performs in place
* encryption/decryption so make sure to 
* pass in non-readonly data.
*/
typedef struct context {
    char key[8];
    char *in;
    char *out;
    size_t inSize;
    size_t outSize;
    int blocks;
    uint64_t subkeys[NUM_SUB_KEYS];
} DESCtx;


/**
* @brief Populating this context is recommeded
* when encrypting/decrypting. It allows the
* all cipher metadata to located in one place
* for easy sanitization.
*/
typedef enum ctx_type {
    EncryptT,
    DecryptT,
} CtxType;

/**
* @brief Specify padding type when
* encrypting and decrypting.
*/
typedef enum pad_type {
    ZeroPad,
    PKCS5Pad,
} PadMode;


typedef enum {
    CRYPT_SUCCESS,        // no errors to report
    CRYPT_INPUT_ERROR,    // any error pertaining to invalid input
    CRYPT_CRITICAL_ERROR, // any error indicating fatal error and immediate exit
} CryptAPI;

/**
* @brief Initialize the DES context by expanding 
* @param ctx DES Context containing block size, input, output and key
*       schedule.
* @return CryptAPI status of initialization when generating blocks
*           and key schedule.
*/
CryptAPI initialize(DESCtx *ctx);

/**
* @brief finalize DES context
* @return CryptAPI status of encryption/decryption
*/
CryptAPI finalize(DESCtx *ctx, CtxType type);


/**
* @brief destroy context info
* @param ctx cipher context.
*/
void sanitize(DESCtx *ctx);

/**
* @brief sBox permutation to be done at each round
* @param block 32 bit block of data to undergo permutation
* @param key 56 bit key
* @return uint32_t sbox permutation for a given subkey
*/
uint32_t sBoxPermutation (const uint32_t block, uint64_t key);

/**
* @brief generate 16 56-bit sub keys
* @param key 56 bit key
* @param subKeys key schedule pointer that is populated dervied
*   from the input key.
*/
void generateKeySchedule(const uint64_t key, uint64_t *subKeys);

/**
* @brief DES Cipher with encrypt/decrypt option
* @param message plaintext or ciphertext
* @param subkeys key schedule for the specified cipher key.
* @param decrypt boolean specifying if decrypt mode is enabled.
*/
void CryptDES(uint64_t *message,uint64_t *subkeys, bool decrypt);

#ifdef __cplusplus 
}
#endif

#endif
