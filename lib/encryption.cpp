#include "encryption.h"
#include <random>
#include <iostream>

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

    std::random_device rd; 
    std::mt19937 gen(rd());
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

std::vector<uint64_t> DesEncryption::encryptCbcMode(std::string a){
    std::vector<uint64_t> encryptBlocks;

    uint64_t ivCipher = _encrypt(m_iv, m_key);

    std::vector<uint64_t> dataBlocks = getChunks(a);

    // xor plaintext blocks with encrypted IV 
    for (uint64_t block: dataBlocks) {
        encryptBlocks.push_back( block ^ ivCipher );
    }

    return encryptBlocks;
}

std::vector<uint64_t> DesEncryption::encryptCbcMode(std::vector<uint64_t> dataBlocks) {
    std::vector<uint64_t> encryptBlocks;

    uint64_t ivCipher = _encrypt(m_iv, m_key);

    // xor plaintext blocks with encrypted IV 
    for (uint64_t block: dataBlocks) {
        encryptBlocks.push_back( block ^ ivCipher );
    }

    return encryptBlocks;
}

std::string DesEncryption::decryptCbcMode(std::vector<uint64_t> encryptedData) {
    std::string pText;
    std::vector<uint64_t> decryptBlocks;

    uint64_t ivCipher = _encrypt(m_iv, m_key);

    // xor ciphertext blocks with encrypted IV 
    for (uint64_t block: encryptedData) {
        decryptBlocks.push_back( block ^ ivCipher );
    }


    for (size_t i = 0; i < decryptBlocks.size(); i++) {
    	Char_Int64 intData;
    	intData.data = __builtin_bswap64(decryptBlocks[i]);
    	std::string s = intData.raw;
    	pText += s.substr(0,8);
    }
    
    return pText;
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
        ullVector.push_back(__builtin_bswap64(text[j]));
        i+=8;
        j++;
    }

    return ullVector;
}

void DesEncryption::initializeNonce() { m_nonce = getRandomValue(); }

void DesEncryption::initializeIV() { m_iv = getRandomValue(); }

uint64_t DesEncryption::getIV() { return m_iv; }

uint64_t DesEncryption::getRandomValue() {
    //TODO: this will do for now
    std::uniform_int_distribution<uint64_t> dis(977, 5849);
    return dis(m_gen);
}
