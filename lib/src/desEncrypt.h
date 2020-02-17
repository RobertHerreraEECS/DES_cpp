#ifndef DES_ENCRYPT_H
#define DES_ENCRYPT_H

#include "encrypt.h"
 #include "desEncrypt.h"
 #include "BitPermutationFunctions.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

#define HELLO 4

#ifdef __cplusplus
extern "C"
{
#endif

	void encryptUsingRandomKey();
	void printIntBinary(int message);
	void printCharHex(char* message);
	void desEncryptionPer64(char* message,char* key);
	void desDecryptionPer64(char* message,char* key);

#ifdef __cplusplus 
}
#endif

#endif
