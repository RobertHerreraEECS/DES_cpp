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


DesEncryption::DesEncryption() {
    m_key = 0x0;
}

DesEncryption::~DesEncryption() {}

uint64_t DesEncryption::getKey() { return m_key; }

void DesEncryption::setKey(uint64_t key) { m_key = key; }

std::string DesEncryption::decryptEcbMode(std::vector<uint64_t> encryptedData) {
    std::string pText;
    std::vector<uint64_t> decryptBlocks;

    for (uint64_t block: encryptedData) {
        decryptBlocks.push_back(_decrypt(block, m_key));
    }

    for (size_t i = 0; i < decryptBlocks.size(); i++) {
    	Char_Int64 intData;
    	intData.data = __builtin_bswap64 (decryptBlocks[i]); // for gcc/clang
    	std::string s = intData.raw;
    	pText += s.substr(0,8);
    }
    
    return pText;
}

std::vector<uint64_t> DesEncryption::encryptEcbMode(std::string a){

    // seperate string into 64 bit blocks (vector)
    std::vector<uint64_t> dataBlocks = getChunks(a);
    std::vector<uint64_t> encryptBlocks;

    for (uint64_t block: dataBlocks) {
        encryptBlocks.push_back(_encrypt(block, m_key));
    }

    return encryptBlocks;
}

std::vector<uint64_t> DesEncryption::encryptEcbMode(std::vector<uint64_t> dataBlocks){

    std::vector<uint64_t> encryptBlocks;

    for (uint64_t block: dataBlocks) {
        encryptBlocks.push_back(_encrypt(block, m_key));
    }

    return encryptBlocks;
}

std::vector<uint64_t> DesEncryption::getChunks(const std::string a){

    int size = 0;
    int remainder = 0;
    std::vector<uint64_t> ullVector;

    size = (int) a.size() / 8;
    remainder = a.size() % 8;

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
        ullVector.push_back(__builtin_bswap64 (text[j]));
        i+=8;
        j++;
    }

    return ullVector;
}
