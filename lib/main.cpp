#include <iostream>
#include <string>
#include "encryption.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "src/desEncrypt.h"
#ifdef __cplusplus
}
#endif


 int main(int argc, char *argv[]){
    std::cout << "=== DES Encryption Program ===" << std::endl;
	
    uint64_t plaintext[2] = {0};
    plaintext[0] = 0x0123456789ABCDEF;
    plaintext[1] = 0x0123456789ABCDEF;
    uint64_t key = 0x133457799BBCDFF1;
    int len = 2;
    uint64_t *ciphertext = desEncryptECB(plaintext,len,key);
    for (int i = 0; i < len; i++) {
    	std::cout << std::hex << ciphertext[i] << std::endl;
    }

    uint64_t *ptext = desDecryptECB(ciphertext,len,key);
    for (int i = 0; i < len; i++) {
    	std::cout << std::hex << ptext[i] << std::endl;
    }

    free(ciphertext);
    free(ptext);

    return 0;
 }
