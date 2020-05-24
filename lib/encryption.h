#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "desEncrypt.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

#ifdef __cplusplus
extern "C"
{
#endif
#include "src/desEncrypt.h"
#ifdef __cplusplus
}
#endif


// DES Cipher Wrapper Class
class DesEncryption {

public:

	DesEncryption();
	~DesEncryption();

    /**
    * @brief encrypt string data in 64 bit chunks
    * @param string data to be encrypted
    * @param key 64 bit key
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t>  encryptEcbMode(std::string);

    std::vector<uint64_t>  encryptEcbMode(std::vector<uint64_t> dataBlocks);


    /**
    * @brief decrypt uint64 vector data
    * @param vector uint64 vector representing ciphertext
    * @param key 64 bit key
    * @return plaintext in string datatype
    */
    std::string decryptEcbMode(std::vector<uint64_t>);

    /**
    * @brief function will convert a string to  a vector of uint64's (unsigned long long)
    * @param string data to be converted to uint64 vector
    * @return plaintext vector in 64 bit chunks
    */
    std::vector<uint64_t> getChunks(const std::string);

    uint64_t getKey();
    void setKey(uint64_t key);

private:

    uint64_t m_key = 0;

};

#endif // ENCRYPTION_H
