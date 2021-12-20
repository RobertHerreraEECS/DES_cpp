#include <iostream>
#include <fstream>
#include <string>
#include "encryption.h"
//#include "desEncrypt.h"

using namespace std;

typedef struct {
    string hexlifiedKey;
    string filename;
    char *data;
} UserInfo;


void unhexlify(char *data) {

}

string hexlify(char *data, size_t size){
    return string("DEADBEEF");
}

void parseArgs(int argc, char *argv[]) {

}

void usage() {
    cout << "usage:" << endl;
    cout << "./main <input_file>" << endl;
}

int main(int argc, char *argv[]){

    if (argc < 2) {
        usage();
        exit(-1);
    }

    parseArgs(argc, argv);

    CryptoDES desCryptCtx;
    const uint8_t key[8] = { 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xfa, 0xde };
    string a = "this text needs to be encrypted and decrypted!!!";
    char* c = const_cast<char*>(a.c_str());

    return 0;
 }
