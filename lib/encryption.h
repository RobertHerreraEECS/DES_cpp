#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "desEncrypt.h"
#include <vector>
#include <string>
#include <cstdlib>
#include <random>

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
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t>  encryptEcbMode(std::string);

    /**
    * @brief encrypt 64 bit chunks using ECB Mode
    * @param 64 bit chunks to be encrypted
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptEcbMode(std::vector<uint64_t> dataBlocks);


    /**
    * @brief decrypt uint64 vector data using ECB Mode
    * @param vector uint64 vector representing ciphertext
    * @return plaintext in string datatype
    */
    std::string decryptEcbMode(std::vector<uint64_t>);

    /**
    * @brief encrypt string data in 64 bit chunks using CBC Mode
    * @param string data to be encrypted
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptCbcMode(std::string a);

    /**
    * @brief encrypt 64 bit chunks using CBC Mode
    * @param string data to be encrypted
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptCbcMode(std::vector<uint64_t> dataBlocks);

    /**
    * @brief decrypt 64 bit chunks using CBC Mode
    * @param string data to be encrypted
    * @return plaintext vector in 64 bit chunks
    */
    std::string decryptCbcMode(std::vector<uint64_t> encryptedData);

    /**
    * @brief decrypt 64 bit chunks using OFB Mode (stream cipher)
    * @param string data to be encrypted
    * @return plaintext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptOfbMode(std::string a);

    /**
    * @brief encrypt 64 bit chunks using OFB Mode (stream cipher)
    * @param string data to be encrypted
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t> encryptOfbMode(std::vector<uint64_t> dataBlocks);

    /**
    * @brief decrypt 64 bit chunks using OFB Mode
    * @param string data to be encrypted
    * @return ciphertext vector in 64 bit chunks
    */
    std::string decryptOfbMode(std::vector<uint64_t> encryptedData);

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

    /**
    * @brief get current IV
    * @return uint64_t IV
    */
    uint64_t getIV();

    /**
    * @brief initialize m_nonce with a random value
    */
    void initializeNonce();

    /**
    * @brief initialize m_iv with a random value
    */
    void initializeIV();

private:

    /**
    * @brief get random 64 bit value
    * @return uint64_t
    */
    uint64_t getRandomValue();

    uint64_t m_key; // encryption key
    uint64_t m_iv; // intialization vector
    uint64_t m_nonce; // nonce for Counter Mode
    std::mt19937 m_gen;

};

#endif // ENCRYPTION_H
