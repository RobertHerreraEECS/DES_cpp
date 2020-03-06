#include <iostream>
#include <string>
#include <vector>
#include "encryption.h"
#include <cstdlib>

#ifdef __cplusplus
extern "C"
{
#endif
#include "src/desEncrypt.h"
#ifdef __cplusplus
}
#endif



union Int64_Char {
 	char raw[8];
 	struct  
 	{
 		uint64_t data;
 	};
 };

 union Char_Int64 {
 	uint64_t data;
 	struct  
 	{
 		char raw[8];
 	};
 };

 int main(int argc, char *argv[]){
    std::cout << "=== DES Encryption Program ===" << std::endl;


    std::string a = "this text needs to be encrypted and decrypted!!!";
    std::cout << "size of data: " << a.size() << std::endl;

    int size = 0;
    int remainder = 0;

    size = (int) a.size() / 8;
    remainder = a.size() % 8;

    std::vector<int> dataChunks;
    for (int i = 0; i < size; i++) {
    	dataChunks.push_back(8);
    }
    if (remainder > 0)
    	dataChunks.push_back(remainder);

    int i,j = 0;
    uint64_t text[(int) dataChunks.size()];
    for (int c: dataChunks) {
    	Int64_Char charData;
        const char * temp = &a.substr(i,c).c_str()[0];
        memcpy(charData.raw,temp,sizeof(uint64_t));
        text[j] = charData.data;
        i+=8;
        j++;
    }

    int len = dataChunks.size();
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t *ciphertext = desEncryptECB(text,len,key);

    std::string out;
    uint64_t *ptext = desDecryptECB(ciphertext,len,key);
    for (int i = 0; i < len; i++) {
    	Char_Int64 intData;
    	intData.data = ptext[i];
    	std::string s = intData.raw;
    	out += s;
    }

    std::cout << out << std::endl;

    free(ciphertext);
    free(ptext);
    

    return 0;
 }
