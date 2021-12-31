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
#include <stdio.h>

#ifdef __cplusplus
}
#endif


// unit tests based off of 
// http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.html
//
// These unit tests are based on `zero-padded` or exact block-sized data

// C layer tests
TEST(singleEncryptTest, singleChunk1) {
    uint64_t C = 0x5b40a0f5413e885;
    uint64_t key = 0x133457799BBCDFF1;

    // load in the payload as big endian
    uint64_t message = 0xefcdab8967452301;
    DESCtx ctx;

    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = (char *) &message;
    ctx.inSize = 8;
    initialize(&ctx);
    finalize(&ctx, EncryptT);

    EXPECT_EQ (C,  *(uint64_t *) ctx.out);
}

TEST(singleEncryptTest, singleChunk2) {
    uint64_t C = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t message = 0x8787878787878787;
    DESCtx ctx;

    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = (char *) &message;
    ctx.inSize = 8;
    initialize(&ctx);
    finalize(&ctx, EncryptT);

    EXPECT_EQ (C,  *(uint64_t *) ctx.out);
}

TEST(singleDecryptTest, singleChunk1) {
    uint64_t C = 0x0;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t message = 0x8787878787878787;
    DESCtx ctx;

    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = (char *) &C;
    ctx.inSize = 8;
    initialize(&ctx);
    finalize(&ctx, DecryptT);

    EXPECT_EQ (*(uint64_t *) ctx.out,  message);	
}

TEST(singleDecryptTest, singleChunk2) {
    uint64_t C = 0x5b40a0f5413e885;
    uint64_t key = 0x133457799BBCDFF1;

    uint64_t message = 0xefcdab8967452301;
    DESCtx ctx;

    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = (char *) &C;
    ctx.inSize = 8;
    initialize(&ctx);
    finalize(&ctx, DecryptT);

    EXPECT_EQ (*(uint64_t *) ctx.out,  message);
}

TEST(encryptionTest, test1) {

    char message[] = "Your lips are smoother than vaseline\r\n";
    uint64_t *ref = NULL;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t ciphertext[5] = {0};
    DESCtx ctx;

    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = message;
    ctx.inSize = strlen(message);

    initialize(&ctx);
    finalize(&ctx, EncryptT);

    ciphertext[0] = 0xedd778e3dd9f99c0;
    ciphertext[1] = 0xee845aca0ba07d72; 
    ciphertext[2] = 0x908143d6a469f247; 
    ciphertext[3] = 0x998435f5782fd5d9; // typo in documentation
    ciphertext[4] = 0x53e6e053b4c98a82; // values in little-endian equivalent

    ref = (uint64_t *) ctx.out;
    for (int i = 0; i < ctx.blocks; i++) {
        EXPECT_EQ (ciphertext[i], ref[i]);
    }
}

TEST(decryptionTest, test1) {

    char message[] = "Your lips are smoother than vaseline\r\n";
    uint64_t *ref = NULL;
    uint64_t key = 0x0E329232EA6D0D73;
    uint64_t a[5];
    uint64_t ciphertext[5];
    DESCtx ctx;

    a[0] = 0x70696c2072756f59;
    a[1] = 0x6d73206572612073; 
    a[2] = 0x7420726568746f6f; 
    a[3] = 0x65736176206e6168;
    a[4] = 0xa0d656e696c;

    ciphertext[0] = 0xedd778e3dd9f99c0;
    ciphertext[1] = 0xee845aca0ba07d72; 
    ciphertext[2] = 0x908143d6a469f247; 
    ciphertext[3] = 0x998435f5782fd5d9; // typo in documentation
    ciphertext[4] = 0x53e6e053b4c98a82; // values in little-endian equivalent
 
    ctx.pad = ZeroPad;
    ctx.op = ECB_Mode;

    memcpy(ctx.key, (char *) &key, KEY_BYTES);
    ctx.in = (char *) ciphertext;
    ctx.inSize = 40;

    initialize(&ctx);
    finalize(&ctx, DecryptT);

    ref = (uint64_t *) ctx.out;
    for (int i = 0; i < 5; i++) {
         EXPECT_EQ (ref[i],  a[i]);
    }
}
