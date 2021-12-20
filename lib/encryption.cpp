#include "encryption.h"
#include <random>
#include <iostream>
#include <cstring>

CryptoDES::CryptoDES() {
    m_key = 0x0;

    std::random_device rd; 
    std::mt19937 gen(rd());
}

CryptoDES::~CryptoDES() {}

uint64_t CryptoDES::getKey() { return m_key; }

void CryptoDES::setKey(uint64_t key) { m_key = key; }

void CryptoDES::encryptECB(char *message, size_t size, const char *key) {
    DESCtx ctx;

    memcpy(ctx.key, key, 8);
    ctx.message = message;
    ctx.messageSize = size; //TODO: modify this to have a better max size

    initialize(&ctx);

    finalize(&ctx, EncryptT);

    sanitize(&ctx);
}

void CryptoDES::decryptECB(char *ciphertext, size_t size, const char *key) {
    DESCtx ctx;

    memcpy(ctx.key, key, 8);
    ctx.message = ciphertext;
    ctx.messageSize = size; //TODO: modify this to have a better max size
    initialize(&ctx);

    finalize(&ctx, DecryptT);
    sanitize(&ctx);
}

void CryptoDES::initializeNonce() { m_nonce = getRandomValue(); }

void CryptoDES::initializeIV() { m_iv = getRandomValue(); }

uint64_t CryptoDES::getIV() { return m_iv; }

uint64_t CryptoDES::getRandomValue() {
    //TODO: this will do for now
    std::uniform_int_distribution<uint64_t> dis(0xa4c8e71b4bad4abf, 0xa4c8e71b4bad4abf);
    return dis(m_gen);
}
