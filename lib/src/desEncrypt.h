#ifndef DES_ENCRYPT_H
#define DES_ENCRYPT_H

#ifdef __cplusplus
extern "C"
{
#endif

	void encryptUsingRandomKey();
	void printIntBinary(int message);
	void printCharHex(char* message);
	void desEncryptionPer64(char* message,char* key);
	void desDecryptionPer64(char* message,char* key);
	uint32_t sBoxPermutation (uint32_t block, uint64_t key);
	uint64_t encrypt(uint64_t message,uint64_t key);

#ifdef __cplusplus 
}
#endif

#endif
