#include <iostream>
#include <string>
#include "encryption.h"
#include "./src/desEncrypt.h"

 int main(int argc, char *argv[]){
    std::cout << "=== DES Encryption Program ===" << std::endl;

    DesEncryption des;
    des.example();

    std::cout << "Encrypting message using random key..." << std::endl;

    encryptUsingRandomKey();

    return 0;
 }
