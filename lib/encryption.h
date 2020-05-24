#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "desEncrypt.h"
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
    * @brief encrypt string data in 64 bit chunks using ECB Mode
    * @param string data to be encrypted
    * @param key 64 bit key
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t>  encryptEcbMode(std::string);

    /**
    * @brief encrypt 64 bit chunks using ECB Mode
    * @param 64 bit chunks to be encrypted
    * @param key 64 bit key
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptEcbMode(std::vector<uint64_t> dataBlocks);


    /**
    * @brief decrypt uint64 vector data using ECB Mode
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

    /**
    * @brief get key currently loaded
    * @return uint64_t key
    */
    uint64_t getKey();

    /**
    * @brief set 64 bit key
    */
    void setKey(uint64_t key);

private:

    uint64_t m_key; // encryption key
    uint64_t m_iv; // intialization vector
    uint64_t m_nonce; // nonce for Counter Mode

};

#endif // ENCRYPTION_H
