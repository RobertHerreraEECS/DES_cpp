#ifndef ENCRYPTION_H
#define ENCRYPTION_H
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
class CryptoDES {

public:

    CryptoDES();
    ~CryptoDES();

    /**
     *  @brief encrypt data in place using DES cipher
     *  in ECB Mode.
     *  @param in input plaintext to be encrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the encrypted output buffer.
     *  @key the key used to encrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void encryptECB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  in ECB Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void decryptECB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

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
    uint64_t getRandU64();

    uint64_t m_key; // encryption key
    uint64_t m_iv; // intialization vector
    uint64_t m_nonce; // nonce for Counter Mode
    std::mt19937 m_gen;

};

#endif // ENCRYPTION_H
