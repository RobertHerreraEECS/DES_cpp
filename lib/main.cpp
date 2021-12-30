#include <iostream>
#include <fstream>
#include <string>
#include "encryption.h"

using namespace std;

typedef struct {
    string hexlifiedKey;
    string filename;
    char *data;
} UserInfo;


uint64_t unhexlify(string hexlified) {
    size_t idx = 0;
    return stoull(hexlified, &idx, 16);
}

string hexlify(uint64_t *unhexlified){
    return to_string((unsigned long long) *unhexlified);
}

void parseArgs(int argc, char *argv[]) {

}

void usage() {
    cout << "usage:" << endl;
    cout << "./main <input_file>" << endl;
}

int main(int argc, char *argv[]){

    const uint64_t key = 0x0E329232EA6D0D73;
    string str_string = "0x0E329232EA6D0D73";
    CryptoDES desCryptCtx;
    ofstream myfile;
    char *out = NULL;
    size_t size = 0;

    if (argc < 2) {
        usage();
        exit(-1);
    }

    parseArgs(argc, argv);

    string a = "Your lips are smoother than vaseline\r\n";
    char* c = const_cast<char*>(a.c_str());

    desCryptCtx.encryptECB(c, a.size(), &out, &size, (const char *)&key);

    myfile.open("output.bin");
    if (myfile.is_open()) {
      cout << "Writing encrypted data to file..." << endl;
      myfile.write(out, size);
    }

    return 0;
 }
