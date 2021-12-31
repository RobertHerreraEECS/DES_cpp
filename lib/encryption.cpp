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

void CryptoDES::encryptECB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));

    ctx->pad = PKCS5Pad;
    ctx->op = ECB_Mode;
    this->encrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::decryptECB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));

    ctx->pad = PKCS5Pad;
    ctx->op = ECB_Mode;
    this->decrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::encryptCBC(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));

    ctx->pad = PKCS5Pad;
    ctx->op = CBC_Mode;
    this->encrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::decryptCBC(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));


    ctx->pad = PKCS5Pad;
    ctx->op = CBC_Mode;
    this->decrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::encryptCFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));

    ctx->pad = PKCS5Pad;
    ctx->op = CFB_Mode;
    this->encrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::decryptCFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));


    ctx->pad = PKCS5Pad;
    ctx->op = CFB_Mode;
    this->decrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::encryptOFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));

    ctx->pad = PKCS5Pad;
    ctx->op = OFB_Mode;
    this->encrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::decryptOFB(char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    DESCtx *ctx = (DESCtx *) malloc(sizeof(DESCtx));


    ctx->pad = PKCS5Pad;
    ctx->op = OFB_Mode;

    this->decrypt(ctx, in, inSize, out, outSize, key);
}

void CryptoDES::decrypt(DESCtx *ctx, char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    memcpy(ctx->key, key, KEY_BYTES);
    ctx->in = in;
    ctx->inSize = inSize;
    initialize(ctx);

    finalize(ctx, DecryptT);

    *outSize = ctx->outSize;
    *out = ctx->out;
}

void CryptoDES::encrypt(DESCtx *ctx, char *in, size_t inSize, char **out, size_t *outSize, const char *key) {
    memcpy(ctx->key, key, KEY_BYTES);
    ctx->in = in;
    ctx->inSize = inSize;
    initialize(ctx);

    finalize(ctx, EncryptT);

    *outSize = ctx->outSize;
    *out = ctx->out;
}


void CryptoDES::initializeNonce() { m_nonce = getRandU64(); }

void CryptoDES::initializeIV() { m_iv = getRandU64(); }

uint64_t CryptoDES::getIV() { return m_iv; }

uint64_t CryptoDES::getRandU64() {
    //TODO: this will do for now
    std::uniform_int_distribution<uint64_t> dis(0xa4c8e71b4bad4abf, 0xa4c8e71b4bad4abf);
    return dis(m_gen);
}
