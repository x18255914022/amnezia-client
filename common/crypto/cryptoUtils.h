#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>

#include <memory>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// Thin wrapper around OpenSSL EVP used for local settings encryption and for
// the API-gateway request/response envelope. Replaces the unmaintained
// QSimpleCrypto library. All functions report failures by returning an empty
// QByteArray (or nullptr) and logging, without throwing.
//
// Wire compatibility note: encryptAes256Cbc/decryptAes256Cbc reproduce the exact
// behaviour of QSimpleCrypto::QBlockCipher (AES-256-CBC, PKCS7 padding, first
// 16 bytes of the IV buffer), so data written by previous app versions stays
// readable and gateway requests keep the same format.
namespace CryptoUtils
{
    // Cryptographically secure random bytes of the requested size.
    QByteArray generateRandomBytes(int size);

    // AES-256-CBC with PKCS7 padding. key must be 32 bytes, iv must be at least
    // 16 bytes (only the first 16 are used, matching the legacy behaviour).
    // WARNING: unauthenticated CBC — kept only for wire-compatibility with the
    // API gateway protocol. Prefer encryptAes256CbcHmac for data at rest.
    QByteArray encryptAes256Cbc(const QByteArray &data, const QByteArray &key, const QByteArray &iv);
    QByteArray decryptAes256Cbc(const QByteArray &data, const QByteArray &key, const QByteArray &iv);

    // Authenticated encryption for data at rest: AES-256-CBC (PKCS7) followed by
    // an HMAC-SHA256 over IV || ciphertext (encrypt-then-MAC). The MAC key is
    // derived from the encryption key with domain-separated SHA-256, so the two
    // keys are independent. Output layout: 'M' || iv(16) || tag(32) || ciphertext.
    // decryptAes256CbcHmac transparently accepts legacy unauthenticated blobs
    // (no leading 'M' tag) for backward compatibility, but newly written data
    // is always authenticated; a tampered tagged blob returns an empty result.
    QByteArray encryptAes256CbcHmac(const QByteArray &data, const QByteArray &key, const QByteArray &iv);
    QByteArray decryptAes256CbcHmac(const QByteArray &data, const QByteArray &key, const QByteArray &iv);

    // Loads an RSA public key from PEM bytes. Returns nullptr on failure.
    // The caller owns the result and must free it with EVP_PKEY_free().
    EVP_PKEY *loadPublicKeyFromPem(const QByteArray &pem);

    // RSA encryption with the given OpenSSL padding (e.g. RSA_PKCS1_PADDING).
    QByteArray rsaEncrypt(const QByteArray &data, EVP_PKEY *publicKey, int padding);
}

#endif // CRYPTOUTILS_H
