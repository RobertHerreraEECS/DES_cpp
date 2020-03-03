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

    uint64_t a[2] = {0};
    uint64_t key = 0;
    desEncryptECB(a,key);

    return 0;
 }
