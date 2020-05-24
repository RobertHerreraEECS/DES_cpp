#include <iostream>
#include <string>
#include "encryption.h"

 int main(int argc, char *argv[]){
    std::cout << "=== DES Encryption Program ===" << std::endl;

    std::string a = "this text needs to be encrypted and decrypted!!!";

    DesEncryption e;
    e.setKey((uint64_t) 0x133457799BBCDFF1);
    std::vector<uint64_t> data = e.encryptEcbMode(a);

    std::string out = e.decryptEcbMode(data);

    std::cout << "message: " << out << std::endl;

    return 0;
 }
