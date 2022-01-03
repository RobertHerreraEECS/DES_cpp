#include <iostream>
#include <fstream>
#include <string>
#include <map>

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


map<string, Operation_T> operation_map = { 
                         { "ecb", ECB_Mode},
                         { "cbc", CBC_Mode},
                         { "ofb", OFB_Mode},
                         { "cfb", CFB_Mode},
                         }; 

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
    cout << "./cryptdes plaintext ciphertext -K deadbeeffacefade -C enc\n";
}


int parseArgs(int argc, char *argv[]) {
    int ret, kflag = 0, cflag = 0;
    int mflag = 0, nflag = 0, pflag = 0;
    
    infile = string(argv[1]);
    outfile = string(argv[2]);

    while ((ret = getopt (argc, argv, "K:C:M:P:N:")) != -1) {
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
            exit(-1);
          }
    }

    if (mflag && !(operation.compare("cbc") ||
                   operation.compare("ofb") ||
                   operation.compare("cfb") ||
                   operation.compare("ecb"))) {
        fprintf (stderr,"Unknown mode of operation..\n");
        usage();
        return 0;
    }

    if (mflag && (operation == "cbc" || operation == "ofb"
        || operation == "cfb") && !nflag) {
        fprintf (stderr,"Missing required `IV` argument -N\n");
        usage();
        return 0;
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
    char *output;
    size_t osize;
    CryptAPI result;

    if (argc < 4) {
        usage();
        exit(-1);
    }
    if (!parseArgs(argc, argv))
    exit(-1);

    desCryptCtx.setKey(unhexlify(hexkey));

    if (operation == "ecb") {
        
    } else if (operation == "cbc" | operation == "cfb"
            || operation == "ofb") {
        desCryptCtx.setIV(unhexlify(ivkey));
    }

    std::ifstream file(infile, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (file.is_open())
    {
        buffer.assign(size, 0);
        file.read(buffer.data(), size);
    } else {
        cout << "error opening file..." << endl;
    }

    switch(operation_map[operation]) {
        case ECB_Mode:
            result = desCryptCtx.encryptECB((char *) buffer.data(),
                                            buffer.size(),
                                            &output,
                                            &osize);
            break;
        case CBC_Mode:
            result = desCryptCtx.encryptCBC((char *) buffer.data(),
                                            buffer.size(), 
                                            &output,
                                            &osize);
            break;
        case OFB_Mode:
            result = desCryptCtx.encryptOFB((char *) buffer.data(),
                                            buffer.size(),
                                            &output,
                                            &osize);
            break;
        case CFB_Mode:
            result = desCryptCtx.encryptCFB((char *) buffer.data(),
                                            buffer.size(),
                                            &output,
                                            &osize);
            break;
        default:
            cout << "Unknown mode of operation" << endl;
            usage();
            exit(-1);
    }
    //desCryptCtx.finish();
    if (result != CRYPT_SUCCESS) {
        cout << "Error occurred with encryption" << endl;
        return result;
    }
    

    std::ofstream ofile(outfile, std::ios::binary | std::ios::ate);
    if (ofile.is_open()) {
      ofile.write(output, osize);
    } else {
        cout << "error opening file.\n";
    }
    return 0;
 }
