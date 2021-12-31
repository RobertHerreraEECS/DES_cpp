#include <iostream>
#include <fstream>
#include <string>
#include "encryption.h"
#include <unistd.h>
#include <stdio.h>

using namespace std;

string infile;
string outfile;
string hexkey;

string cipherMode;
string operation;
string ivkey;
string padmode;

uint64_t unhexlify(string hexlified) {
    size_t idx = 0;
    return stoull(hexlified, &idx, 16);
}

string hexlify(uint64_t *unhexlified){
    return to_string((unsigned long long) *unhexlified);
}

void usage() {
    cout << "usage:\n" << endl;
    cout << "./main INPUT_FILE OUTPUT_FILE -K KEY <OPTIONS...>\n";
    cout << "-C [enc | dec] (required): cipher mode\n";
    cout << "-M [ecb | cbc | cfb | ofb]: (ecb by default)\n";
    cout << "-K [hexlifed 8-byte value] (required): 8-byte hexlified key\n";
    cout << "-N [hexlifed 8-byte value]: 8-byte IV used in chaining modes.\n";
    cout << "-P [zero | pkcs] (pkcs by default)";
    cout << "\n\ninfo:\n";
    cout << "--- DES Encrypt ---\n";
    cout << "This program is capable of encrypting/decrypting an input file using the\n";
    cout << "DES cipher. The encrypted/decrypted blobs are compatible with\n";
    cout << "OpenSSL and have been tested against OpenSSL-generated\n";
    cout << "encrypted/decrypted blobs.\n";
    cout << "\n\nexample:\n";
    cout << "./main plaintext ciphertext -K deadbeeffacefade -C enc\n";
}


int parseArgs(int argc, char *argv[]) {
    int ret, kflag = 0, cflag = 0;
    int mflag = 0, nflag = 0, pflag = 0;
    
    infile = string(argv[1]);
    outfile = string(argv[2]);

    while ((ret = getopt (argc, argv, "K:C:M:P:")) != -1) {
        switch (ret)
          {
          case 'C':
            cflag = 1;
            cipherMode = string(optarg);
            break;
          case 'M':
            mflag = 1;
            operation = string(optarg);
            break;
          case 'K':
            kflag = 1;
            hexkey = string(optarg);
            break;
          case 'N':
            nflag = 1;
            ivkey = string(optarg);
            break;
          case 'P':
            pflag = 1;
            padmode = string(optarg);
            break;
          case '?':
            if (optopt == 'K' || optopt == 'M' || optopt == 'C' || optopt == 'P') {
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 0;
            } else if (isprint(optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                return 0;
            } else {
                fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
                return 0;
            }
            break;
          default:
            usage();
            abort();
          }
    }

    if (!kflag || !cflag) {
        fprintf (stderr,"Missing required arguments\n");
        usage();
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[]){

    CryptoDES desCryptCtx;
    std::vector<char> buffer;
    uint64_t key = 0x0E329232EA6D0D73;
    char *output;
    size_t osize;

    if (argc < 4) {
        usage();
        exit(-1);
    }
    if (!parseArgs(argc, argv))
    exit(-1);

    desCryptCtx.setKey(unhexlify(hexkey));

    std::ifstream file(infile, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (file.is_open())
    {
        buffer.assign(size, 0);
        file.read(buffer.data(), size);
    } else {
        cout << "error opening file...\n";
    }

    cout << string(buffer.begin(), buffer.end()) << endl;

    //TODO: finish out input-based modes
    desCryptCtx.encryptCFB((char *) buffer.data(), buffer.size(), &output, &osize, (const char *)&key);

    std::ofstream ofile(outfile, std::ios::binary | std::ios::ate);
    if (ofile.is_open()) {
      cout << "Writing encrypted data to file..." << endl;
      ofile.write(output, osize);
    } else {
        cout << "error opening file.\n";
    }
    return 0;
 }
