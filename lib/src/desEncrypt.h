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

	void desEncryptECB();
	uint32_t sBoxPermutation (const uint32_t block, uint64_t key);
	void generateSubKeys(const uint64_t key, uint64_t *subKeys);
	uint64_t encrypt(const uint64_t message,const uint64_t key);
	uint64_t decrypt(const uint64_t message,const uint64_t key);
	uint64_t DES(const uint64_t message, const uint64_t key, const bool decrypt);

#ifdef __cplusplus 
}
#endif

#endif
