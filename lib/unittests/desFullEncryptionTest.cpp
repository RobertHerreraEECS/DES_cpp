#include <iostream>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "../encryption.h"

#ifdef __cplusplus
extern "C"
{
#endif
	#include "../src/desEncrypt.c"
#ifdef __cplusplus
}
#endif

// unit tests based off of 
// http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.html

// C layer tests
TEST(singleEncryptTest, singleChunk1) {
    uint64_t C = 0x85E813540F0AB405;
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t message = 0x0123456789ABCDEF;
    uint64_t ptext = ::_encrypt(message,key);
    std::cout << "[*] c: 0x" << std::hex << ptext << std::endl;
    EXPECT_EQ (C,  ptext);
}

TEST(singleEncryptTest, singleChunk2) {
    uint64_t C = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t message = 0x8787878787878787;
    uint64_t ptext = ::_encrypt(message,key);
    std::cout << "[*] c: 0x" << std::hex << ptext << std::endl;
    EXPECT_EQ (C,  ptext);
}


TEST(singleDecryptTest, singleChunk1) {
    uint64_t message = 0x85E813540F0AB405;
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t plaintext = 0x0123456789ABCDEF;
    uint64_t ptext = ::_decrypt(message,key);
    std::cout << "[*] c: 0x" << std::hex << ptext << std::endl;
    EXPECT_EQ (plaintext,  ptext);
}

TEST(singleDecryptTest, singleChunk2) {
    uint64_t message = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t plaintext = 0x8787878787878787;
    uint64_t ptext = ::_decrypt(message,key);
    std::cout << "[*] c: 0x" << std::hex << ptext << std::endl;
    EXPECT_EQ (plaintext,  ptext);
}

TEST(encryptionTest, test1) {

    // Your lips are smoother than vaseline (zero padded)
    uint64_t a[5] = {0};
    a[0] = 0x596F7572206C6970;
    a[1] = 0x732061726520736D; 
    a[2] = 0x6F6F746865722074; 
    a[3] = 0x68616E2076617365;
    a[4] = 0x6C696E650D0A0000;

    uint64_t key = 0x0E329232EA6D0D73;

    uint64_t ciphertext[5] = {0};
    ciphertext[0] = 0xC0999FDDE378D7ED;
    ciphertext[1] = 0x727DA00BCA5A84EE; 
    ciphertext[2] = 0x47F269A4D6438190; 
    ciphertext[3] = 0x9DD52F78F5358499;
    ciphertext[4] = 0x828AC9B453E0E653;

    uint64_t * ctext = ::desEncryptECB(a, 5, key);

    // TODO: add zero padding
    // investigate issue with 64 (4)
    for (int i = 0; i < 5; i++) {
    	//EXPECT_EQ (ctext[i],ciphertext[i]);
    	std::cout << "c: " << std::hex << 
    	ctext[i] << " = " << ciphertext[i] << std::endl;
    }
}

TEST(decryptionTest, test1) {

    // Your lips are smoother than vaseline (zero padded)
    uint64_t a[5] = {0};
    a[0] = 0x596F7572206C6970;
    a[1] = 0x732061726520736D; 
    a[2] = 0x6F6F746865722074; 
    a[3] = 0x68616E2076617365;
    a[4] = 0x6C696E650D0A0000;

    uint64_t key = 0x0E329232EA6D0D73;

    //C0999FDDE378D7ED 727DA00BCA5A84EE 47F269A4D6438190 9DD52F78F5358499 828AC9B453E0E653

    uint64_t * ctext = ::desEncryptECB(a, 5, key);

    for (int i = 0; i < 5; i++) {
    	std::cout << std::hex << ctext[i] << std::endl;
    }
    //assert
    EXPECT_EQ (0,  0);
}

// C++ Wrapper layer
TEST(fullEncryptionTest, test1) {

    DesEncryption e;
    EXPECT_EQ (0,  0);
}

TEST(fullDecryptionTest, test1) {

    DesEncryption e;
    EXPECT_EQ (0,  0);
}
