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

	//DesEncryption();
	//~DesEncryption();

    /**
    * @brief encrypt string data in 64 bit chunks
    * @param string data to be encrypted
    * @param key 64 bit key
    * @return ciphertext vector in 64 bit chunks
    */
    std::vector<uint64_t>  encryptData(std::string,uint64_t key);


    /**
    * @brief decrypt uint64 vector data
    * @param vector uint64 vector representing ciphertext
    * @param key 64 bit key
    * @return plaintext in string datatype
    */
    std::string decryptData(std::vector<uint64_t>,uint64_t key);

private:

	/**
    * @brief function will convert a string to  a vector of uint64's (unsigned long long)
    * @param string data to be converted to uint64 vector
    * @return plaintext vector in 64 bit chunks
    */
    std::vector<uint64_t> ullFromString(std::string);


};

#endif // ENCRYPTION_H
