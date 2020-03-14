#include "encryption.h"

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


std::vector<uint64_t> DesEncryption::ullFromString(std::string a){

    int size = 0;
    int remainder = 0;
    std::vector<uint64_t> ullVector;

    size = (int) a.size() / 8;
    remainder = a.size() % 8;


    std::cout << a << std::endl;

    std::vector<int> dataChunks;
    for (int i = 0; i < size; i++) {
    	dataChunks.push_back(8);
    }
    if (remainder > 0)
    	dataChunks.push_back(remainder);

    int i,j;
    i = j = 0;
    uint64_t text[(int) dataChunks.size()];
    for (int c: dataChunks) {
    	Int64_Char charData;
        const char * temp = &(a.substr(i,c).c_str()[0]);
        memcpy(charData.raw,temp,sizeof(uint64_t));
        text[j] = charData.data;
        ullVector.push_back(charData.data);
        i+=8;
        j++;
    }
    return ullVector;
}

std::string DesEncryption::decryptData (std::vector<uint64_t> encryptedData, 
                                        uint64_t key) {
    std::string out;
    int len = encryptedData.size();
    uint64_t *ptext = ::desDecryptECB(encryptedData.data(),len,key);

    for (int i = 0; i < len; i++) {
    	Char_Int64 intData;
    	intData.data = ptext[i];
    	std::string s = intData.raw;
    	out += s;
    }
    free(ptext);
    return out;
}

std::vector<uint64_t> DesEncryption::encryptData (std::string a, uint64_t key){

    std::vector<uint64_t> encryptedData;
    auto plaintext = ullFromString(a);
	int len = plaintext.size();
    uint64_t *ciphertext = ::desEncryptECB(plaintext.data(),len,key);

    for (int i = 0; i < len; i++) {
        encryptedData.push_back(ciphertext[i]);
    }
    free(ciphertext);
    return encryptedData;
}
