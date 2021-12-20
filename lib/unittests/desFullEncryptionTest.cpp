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

    // load in the payload as big endian
    uint64_t message = 0xefcdab8967452301;
    DESCtx ctx;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &message;
    ctx.messageSize = 8;
    initialize(&ctx);
    finalize(&ctx, EncryptT);

    printf("%llx\n", *(uint64_t *) ctx.message);
    EXPECT_EQ (C,  *(uint64_t *)ctx.message);
}

TEST(singleEncryptTest, singleChunk2) {
    uint64_t C = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t message = 0x8787878787878787;
    DESCtx ctx;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &message;
    ctx.messageSize = 8;
    initialize(&ctx);
    finalize(&ctx, EncryptT);

    EXPECT_EQ (C,  *(uint64_t *)ctx.message);
}

TEST(singleDecryptTest, singleChunk1) {
    uint64_t C = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t message = 0x8787878787878787;
    DESCtx ctx;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &C;
    ctx.messageSize = 8;
    initialize(&ctx);
    finalize(&ctx, DecryptT);

    EXPECT_EQ (message,  *(uint64_t *)ctx.message);	
}


TEST(singleDecryptTest, singleChunk2) {
    uint64_t C = 0x85E813540F0AB405;
    uint64_t key = 0x133457799BBCDFF1;

    // load in as big endian
    uint64_t message = 0xefcdab8967452301;
    DESCtx ctx;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &C;
    ctx.messageSize = 8;
    initialize(&ctx);
    finalize(&ctx, DecryptT);

    EXPECT_EQ (message,  *(uint64_t *)ctx.message);
}

TEST(encryptionTest, test1) {

    // Your lips are smoother than vaseline (zero padded)
    char message[] = "Your lips are smoother than vaseline\r\n";
    uint64_t *ref = NULL;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t ciphertext[5] = {0};
    DESCtx ctx;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &message;

    ctx.messageSize = strlen(message);

    initialize(&ctx);
    finalize(&ctx, EncryptT);

    ciphertext[0] = 0xC0999FDDE378D7ED;
    ciphertext[1] = 0x727DA00BCA5A84EE; 
    ciphertext[2] = 0x47F269A4D6438190; 
    ciphertext[3] = 0xD9D52F78F5358499; // typo in documentation
    ciphertext[4] = 0x828AC9B453E0E653;

    ref = (uint64_t *) &message;
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ (ciphertext[i], *ref++);
    }
}

/*
TEST(decryptionTest, test1) {

    // Your lips are smoother than vaseline (zero padded)
    char message[] = "Your lips are smoother than vaseline\r\n";
    uint64_t *ref = NULL;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t a[5];
    uint64_t ciphertext[5];
    DESCtx ctx;

    a[0] = 0x596F7572206C6970;
    a[1] = 0x732061726520736D; 
    a[2] = 0x6F6F746865722074; 
    a[3] = 0x68616E2076617365;
    a[4] = 0x6C696E650D0A0000;

    ciphertext[0] = 0xC0999FDDE378D7ED;
    ciphertext[1] = 0x727DA00BCA5A84EE; 
    ciphertext[2] = 0x47F269A4D6438190; 
    ciphertext[3] = 0xD9D52F78F5358499; // typo in documentation
    ciphertext[4] = 0x828AC9B453E0E653;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.message = (char *) &message;

    ctx.messageSize = strlen(message);
    // TODO: need to do a ciphertext size

    initialize(&ctx);
    finalize(&ctx, EncryptT);

    for (int i = 0; i < 5; i++) {
         EXPECT_EQ (p[i],  a[i]);
    }
}

// C++ Wrapper layer
TEST(fullEncryptionTest, test1) {

    uint64_t ciphertext[5] = {0};
    ciphertext[0] = 0xC0999FDDE378D7ED;
    ciphertext[1] = 0x727DA00BCA5A84EE; 
    ciphertext[2] = 0x47F269A4D6438190; 
    ciphertext[3] = 0xD9D52F78F5358499; //typo in documentation
    ciphertext[4] = 0x828AC9B453E0E653;

    // TODO: add zero padding
    std::string a = "Your lips are smoother than vaseline\r\n";

    uint64_t key = 0x0E329232EA6D0D73;

    CryptoDES e;
    e.setKey(key);
    std::vector<uint64_t> data = e.encryptEcbMode(a);

    int i = 0;
    for (uint64_t c: data) {
       EXPECT_EQ (c,  ciphertext[i]);
       i++;
    }

}

TEST(fullDecryptionTest, test1) {

    std::vector<uint64_t> ciphertext;
    ciphertext.push_back(0xC0999FDDE378D7ED);
    ciphertext.push_back(0x727DA00BCA5A84EE); 
    ciphertext.push_back(0x47F269A4D6438190); 
    ciphertext.push_back(0xD9D52F78F5358499); // typo in documentation
    ciphertext.push_back(0x828AC9B453E0E653);

    // TODO: add zero padding
    std::string a = "Your lips are smoother than vaseline\r\n";

    uint64_t key = 0x0E329232EA6D0D73;
    CryptoDES e;
    e.setKey(key);

    std::string out = e.decryptEcbMode(ciphertext);

    EXPECT_EQ (out,  a);
}
*/
