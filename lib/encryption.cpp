#include "encryption.h"
#include <random>
#include <iostream>
#include <string>
#include <cstring>



CryptoDES::CryptoDES() {
    m_key = 0x0;

    std::random_device rd; 
    std::mt19937 gen(rd());
}

CryptoDES::~CryptoDES() {}

uint64_t CryptoDES::getKey() { return m_key; }

void CryptoDES::setKey(uint64_t key) { m_key = key; }

void CryptoDES::setIV(uint64_t iv) { m_iv = iv; }


CryptAPI CryptoDES::encryptECB(char *in, 
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    CryptAPI ret;
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;

    ctx->pad = PKCS5Pad;
    ctx->op = ECB_Mode;
    ret = this->encrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
    return ret;
}

CryptAPI CryptoDES::decryptECB(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;

    ctx->pad = PKCS5Pad;
    ctx->op = ECB_Mode;
    return this->decrypt(ctx, in, inSize, out, outSize,  (const char *) &m_key);
}

CryptAPI CryptoDES::encryptCBC(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;

    ctx->pad = PKCS5Pad;
    ctx->op = CBC_Mode;
    return this->encrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
}

CryptAPI CryptoDES::decryptCBC(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;


    ctx->pad = PKCS5Pad;
    ctx->op = CBC_Mode;
    return this->decrypt(ctx, in, inSize, out, outSize,  (const char *) &m_key);
}

CryptAPI CryptoDES::encryptCFB(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;

    ctx->pad = PKCS5Pad;
    ctx->op = CFB_Mode;
    return this->encrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
}

CryptAPI CryptoDES::decryptCFB(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));


    ctx->pad = PKCS5Pad;
    ctx->op = CFB_Mode;
    return this->decrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
}

CryptAPI CryptoDES::encryptOFB(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;

    ctx->pad = PKCS5Pad;
    ctx->op = OFB_Mode;
    return this->encrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
}

CryptAPI CryptoDES::decryptOFB(char *in,
                           size_t inSize,
                           char **out,
                           size_t *outSize){
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));
    m_ctx = ctx;


    ctx->pad = PKCS5Pad;
    ctx->op = OFB_Mode;

    return this->decrypt(ctx, in, inSize, out, outSize, (const char *) &m_key);
}

CryptAPI CryptoDES::decrypt(DESCtx *ctx,
                        char *in, size_t inSize,
                        char **out,
                        size_t *outSize,
                        const char *key) {
    CryptAPI ret;
    memcpy(ctx->key, key, KEY_BYTES);
    ctx->in = in;
    ctx->inSize = inSize;
    initialize(ctx);

    ret = finalize(ctx, DecryptT);

    *outSize = ctx->outSize;
    *out = ctx->out;
    return ret; 
}

CryptAPI CryptoDES::encrypt(DESCtx *ctx,
                        char *in,
                        size_t inSize,
                        char **out,
                        size_t *outSize,
                        const char *key) {
    CryptAPI ret;
    memcpy(ctx->key, key, KEY_BYTES);
    ctx->in = in;
    ctx->inSize = inSize;
    initialize(ctx);

    ret = finalize(ctx, EncryptT);

    *outSize = ctx->outSize;
    *out = ctx->out;
    return ret;
}

void CryptoDES::finish() {
   sanitize(m_ctx); 
}

void CryptoDES::initializeNonce() { m_nonce = getRandU64(); }

void CryptoDES::initializeIV() { m_iv = getRandU64(); }

uint64_t CryptoDES::getIV() { return m_iv; }

uint64_t CryptoDES::getRandU64() {
    //TODO: this will do for now
    std::uniform_int_distribution<uint64_t> dis(0xa4c8e71b4bad4abf, 0xa4c8e71b4bad4abf);
    return dis(m_gen);
}
