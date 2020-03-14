#ifndef DES_ENCRYPT_H
#define DES_ENCRYPT_H

#ifdef __cplusplus
extern "C"
{
#endif

	#include <stdio.h>
	#include <stdlib.h>
	#include <stdbool.h>
	#include <string.h>

	#include "permTables.h"
    
    /**
    * @brief Encrypt an array of 64 bit data with a 64 bit key
    * @param message array of 64 bit data
    * @param len length of the array
    * @param key 64 bit key
    * @return ciphertext array encrypted 64 bit data
    */
	uint64_t * desEncryptECB(uint64_t *message, int len, uint64_t key);

    /**
    * @brief Decrypt an array of 64 bit data with a 64 bit key
    * @param ciphertext array of 64 bit data
    * @param len the length of the array
    * @param key 64 bit key
    * @param plaintext array encrypted 64 bit data
    * @return uint64_t array of 64 bit ciphertext with 64 bit key
    */
	uint64_t * desDecryptECB(uint64_t *ciphertext, int len, uint64_t key);

    /**
    * @brief sBox permutation to be done at each round
    * @param 32 bit block of data to undergo permutation
    * @param key 56 bit key
    * @return uint32_t sbox permutation for a given subkey
    */
	uint32_t sBoxPermutation (const uint32_t block, uint64_t key);

    /**
    * @brief generate 16 56-bit sub keys
    * @param key 56 bit key
    * @param array of 56 bit sub keys
    */
	void generateSubKeys(const uint64_t key, uint64_t *subKeys);

    /**
    * @brief Encrypt an array of 64 bit data
    * @param message of 64 bit data
    * @param key 64 bit key
    * @return uint64_t 64 bit ciphertext
    */
	uint64_t _encrypt(const uint64_t message,const uint64_t key);

   /**
    * @brief Decrypt an array of 64 bit data
    * @param ciphertext of 64 bit data
    * @param key 64 bit key
    * @return uint64_t 64 bit plaintext
    */
	uint64_t _decrypt(const uint64_t message,const uint64_t key);

    /**
    * @brief Encrypt an array of 64 bit data with a 64 bit key
    * @param message array of 64 bit data (either plain or cipertext)
    * @param key 64 bit key
    * @param decrypt bool specifying the order that the subkeys are applied
    * @return uint64_t array of 64 bit ciphertext with 64 bit key
    */
	uint64_t DES(const uint64_t message, const uint64_t key, const bool decrypt);

#ifdef __cplusplus 
}
#endif

#endif
