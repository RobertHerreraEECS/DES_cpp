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

#ifdef __cplusplus 
}
#endif

#endif
