#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string signData(const std::string data, const std::string privateKey) {
    // Convert the private key from a string to an OpenSSL BIGNUM
    BIGNUM* privKeyBN = BN_new();
    BN_hex2bn(&privKeyBN, privateKey.c_str());

    // Create an EC_KEY object using the private key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, privKeyBN);

    // Generate the data hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    // Create an ECDSA signature structure
    ECDSA_SIG* sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, key);
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);

    // Convert the signature components to hexadecimal strings
    std::string signature;
    char* rHex = BN_bn2hex(r);
    char* sHex = BN_bn2hex(s);
    signature += rHex;
    signature += sHex;

    // Clean up resources
    OPENSSL_free(rHex);
    OPENSSL_free(sHex);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    BN_free(privKeyBN);

    return signature;
}

bool verifyDataSignature(const std::string data, const std::string publicKey, const std::string signature) {
    // Convert the public key from a string to an OpenSSL EC_POINT
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pubKey = EC_POINT_new(group);
    EC_POINT_hex2point(group, publicKey.c_str(), pubKey, nullptr);

    // Create an EC_KEY object using the public key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_public_key(key, pubKey);

    // Generate the data hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    // Convert the signature from a hexadecimal string to an ECDSA_SIG structure
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_hex2bn(&r, signature.substr(0, signature.length() / 2).c_str());
    BN_hex2bn(&s, signature.substr(signature.length() / 2).c_str());
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    // Verify the signature
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, key);

    // Clean up resources
    ECDSA_SIG_free(sig);
    EC_POINT_free(pubKey);
    EC_KEY_free(key);
    EC_GROUP_free(group);
    BN_free(r);
    BN_free(s);

    return (result == 1);
}