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

/*
*  CryptoDES Class
*
*  Use the cipher wrapper class to encrypt/decrypt 
**/

// DES Cipher Wrapper Class
class CryptoDES {

public:

    CryptoDES();
    ~CryptoDES();

    /**
     *  @brief encrypt data in place using DES cipher
     *  in ECB Mode. The user is responsible for sanitizing the
     *  context after use. (See `finish`)
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
     *  @brief encrypt data in place using DES cipher
     *  in CBC Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void encryptCBC(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  in CBC Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void decryptCBC(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief encrypt data in place using DES cipher
     *  in CFB Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void encryptCFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  in CFB Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void decryptCFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);


    /**
     *  @brief encrypt data in place using DES cipher
     *  in OFB Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void encryptOFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  in OFB Mode.
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void decryptOFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  @param ctx DES Crypto Context
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void encrypt(DESCtx *ctx,char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
     *  @brief decrypt data in place using DES cipher
     *  @param ctx DES Crypto Context
     *  @param in input plaintext to be decrypted
     *  @param inSize the size of the input plaintext
     *  @param out output buffer containing encrypted data.
     *  @param outSize size of the decrypted output buffer.
     *  @key the key used to decrypt data. This key is to
     *  be 8 bytes in length. If longer than 8 bytes, only
     *  the first 8 are copied and used.
     **/
    void decrypt(DESCtx *ctx,char *in, size_t inSize, char **out, size_t *outSize, const char *key);

    /**
    * @brief sanitize the generated crypto context and free
    *   allocated buffers.
    */
    CryptAPI finish();

    /**
    * @brief get key currently loaded
    * @return uint64_t key
    */
    uint64_t getKey();

    /**
    * @brief set 64 bit key.
    *
    * Use unhexlify to transform a hexlified key.
    */
    void setKey(uint64_t key);

    /**
    * @brief set 64 bit key
    *
    * Use unhexlify to transform a hexlified key.
    */
    void setIV(uint64_t key);

    /**
    * @brief get current IV loaded into memory.
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

    uint64_t m_key;                // encryption key
    uint64_t m_iv;                 // intialization vector
    uint64_t m_nonce;              // nonce for Counter Mode
    PadMode  m_padMode = PKCS5Pad; // default padding mode
    std::mt19937 m_gen;

};

#endif // ENCRYPTION_H
