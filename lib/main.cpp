#include <iostream>
#include <string>
#include "encryption.h"

 int main(int argc, char *argv[]){
    std::cout << "=== DES Encryption Program ===" << std::endl;

    std::string a = "this text needs to be encrypted and decrypted!!!";

    DesEncryption e;
    uint64_t key = 0x133457799BBCDFF1;
    std::vector<uint64_t> data = e.encryptEcbMode(a);

    for (int64_t c: data) {
        std::cout << std::hex << c << std::endl;
    }
    
    std::string out = e.decryptEcbMode(data);

    std::cout << "message: " << out << std::endl;

    return 0;
 }
