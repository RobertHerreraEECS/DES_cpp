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
    std::cout << "Encrypting message using random key..." << std::endl;

    encryptUsingRandomKey();

    return 0;
 }
