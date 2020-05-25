#include <iostream>
#include <string>
#include "encryption.h"

using namespace std;

int main(int argc, char *argv[]){
    cout << "=== DES Encryption Program ===" << endl;

    string a = "this text needs to be encrypted and decrypted!!!";

    DesEncryption e;
    e.setKey((uint64_t) 0x133457799BBCDFF1);

    cout << "ECB Mode:" << endl;
    vector<uint64_t> d = e.encryptEcbMode(a);
    for (uint64_t c: d)
    cout << hex << c << endl;

    string ptext = e.decryptEcbMode(d);
    cout << "message: " << ptext << endl;

    cout << "CBC Mode:" << endl;
    e.initializeIV();
    vector<uint64_t> data = e.encryptCbcMode(a);
    for (uint64_t c: data)
    cout << hex << c << endl;

    string out = e.decryptCbcMode(data);
    cout << "message: " << out << endl;


    cout << "OFB Mode:" << endl;
    vector<uint64_t> ctxt = e.encryptOfbMode(a);
    for (uint64_t c: ctxt)
    cout << hex << c << endl;

    string ptxt = e.decryptOfbMode(ctxt);
    cout << "message: " << ptxt << endl;

    return 0;
 }
