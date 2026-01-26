#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "crypto.hpp"
#include "test_utils.hpp"

using ::testing::ElementsAre;

namespace {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string getPublicKeyPEM(EVP_PKEY* pkey)
{
    BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_PUBKEY(bio.get(), pkey);
    char* data;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

std::string getPrivateKeyPEM(EVP_PKEY* pkey)
{
    BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr,
                             nullptr);
    char* data;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

EVP_PKEY_ptr generateKey(mw::SignatureAlgorithm algo)
{
    EVP_PKEY* pkey_raw = nullptr;

    int type = EVP_PKEY_RSA;
    switch (algo) {
        case mw::SignatureAlgorithm::RSA_PSS_SHA512:
        case mw::SignatureAlgorithm::RSA_V1_5_SHA256:
            type = EVP_PKEY_RSA;
            break;
        case mw::SignatureAlgorithm::ECDSA_P256_SHA256:
        case mw::SignatureAlgorithm::ECDSA_P384_SHA384:
            type = EVP_PKEY_EC;
            break;
        case mw::SignatureAlgorithm::ED25519:
            type = EVP_PKEY_ED25519;
            break;
        default:
            return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(type, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY_keygen_init(ctx.get());

    if (algo == mw::SignatureAlgorithm::RSA_PSS_SHA512 ||
        algo == mw::SignatureAlgorithm::RSA_V1_5_SHA256) {
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048);
    } else if (algo == mw::SignatureAlgorithm::ECDSA_P256_SHA256) {
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1);
    } else if (algo == mw::SignatureAlgorithm::ECDSA_P384_SHA384) {
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1);
    }

    EVP_PKEY_keygen(ctx.get(), &pkey_raw);
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

std::vector<unsigned char> sign(mw::SignatureAlgorithm algo, EVP_PKEY* pkey, const std::string& data)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    const EVP_MD* md = nullptr;
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    switch (algo) {
        case mw::SignatureAlgorithm::RSA_PSS_SHA512:
            md = EVP_sha512();
            break;
        case mw::SignatureAlgorithm::RSA_V1_5_SHA256:
        case mw::SignatureAlgorithm::HMAC_SHA256:
        case mw::SignatureAlgorithm::ECDSA_P256_SHA256:
            md = EVP_sha256();
            break;
        case mw::SignatureAlgorithm::ECDSA_P384_SHA384:
            md = EVP_sha384();
            break;
        case mw::SignatureAlgorithm::ED25519:
            md = nullptr;
            break;
    }

    auto init_sign = [&]() {
        EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, md, nullptr, pkey);
        if (algo == mw::SignatureAlgorithm::RSA_PSS_SHA512) {
            EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
        }
    };

    init_sign();
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0)
    {
        return {};
    }

    // Re-initialize for the actual signing
    EVP_MD_CTX_reset(md_ctx.get());
    init_sign();

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0)
    {
        return {};
    }
    signature.resize(sig_len);

    return signature;
}

} // namespace

TEST(Hash, CanHashSHA256)
{
    ASSIGN_OR_FAIL(auto hash, mw::SHA256Hasher().hashToBytes("aaa"));
    EXPECT_THAT(hash,
                ElementsAre(0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
                            0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c,
                            0x4a, 0xc8, 0x9b, 0x1a, 0xdf, 0x57, 0xf2, 0x8f,
                            0x2f, 0x9d, 0x09, 0xaf, 0x10, 0x7e, 0xe8, 0xf0));

    ASSIGN_OR_FAIL(std::string result, mw::SHA256Hasher().hashToHexStr("aaa"));
    EXPECT_EQ(result,
              "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0");
}

TEST(Hash, CanHashSHA256Half)
{
    ASSIGN_OR_FAIL(auto hash, mw::SHA256HalfHasher().hashToBytes("aaa"));
    EXPECT_THAT(hash,
                ElementsAre(0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1,
                            0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c));

    ASSIGN_OR_FAIL(std::string result,
                   mw::SHA256HalfHasher().hashToHexStr("aaa"));
    EXPECT_EQ(result,
              "9834876dcfb05cb167a5c24953eba58c");
}

TEST(Signature, CanVerifySignatures)
{
    std::string data = "test message";

    struct TestCase {
        mw::SignatureAlgorithm algo;
        std::string name;
    };

    std::vector<TestCase> test_cases = {
        {mw::SignatureAlgorithm::RSA_PSS_SHA512, "rsa_pss_sha512"},
        {mw::SignatureAlgorithm::RSA_V1_5_SHA256, "rsa_v1_5_sha256"},
        {mw::SignatureAlgorithm::ECDSA_P256_SHA256, "ecdsa_p256_sha256"},
        {mw::SignatureAlgorithm::ECDSA_P384_SHA384, "ecdsa_p384_sha384"},
        {mw::SignatureAlgorithm::ED25519, "ed25519"}
    };

    for (const auto& tc : test_cases) {
        SCOPED_TRACE(tc.name);
        auto pkey = generateKey(tc.algo);
        ASSERT_TRUE(pkey) << "Failed to generate key for " << tc.name;

        std::string pub_key = getPublicKeyPEM(pkey.get());
        auto signature = sign(tc.algo, pkey.get(), data);
        ASSERT_FALSE(signature.empty()) << "Failed to sign for " << tc.name;

        mw::Crypto crypto;
        ASSIGN_OR_FAIL(bool valid, crypto.verifySignature(
            tc.algo, pub_key, signature, data));
        EXPECT_TRUE(valid) << "Failed to verify valid signature for " << tc.name;

        // Test invalid signature
        if (!signature.empty()) {
            signature[0] ^= 0xFF;
            ASSIGN_OR_FAIL(bool invalid, crypto.verifySignature(
                tc.algo, pub_key, signature, data));
            EXPECT_FALSE(invalid) << "Verified invalid signature for " << tc.name;
        }
    }
}

TEST(Signature, CanVerifyHMAC)
{
    std::string data = "test message";
    std::string key(32, 'k');
    mw::SignatureAlgorithm algo = mw::SignatureAlgorithm::HMAC_SHA256;

    EVP_PKEY_ptr pkey(EVP_PKEY_new_mac_key(
        EVP_PKEY_HMAC, nullptr,
        reinterpret_cast<const unsigned char*>(key.data()), key.size()),
                      EVP_PKEY_free);
    ASSERT_TRUE(pkey);

    auto signature = sign(algo, pkey.get(), data);
    ASSERT_FALSE(signature.empty());

    mw::Crypto crypto;
    ASSIGN_OR_FAIL(bool valid, crypto.verifySignature(algo, key, signature, data));
    EXPECT_TRUE(valid);

    signature[0] ^= 0xFF;
    ASSIGN_OR_FAIL(bool invalid, crypto.verifySignature(algo, key, signature, data));
    EXPECT_FALSE(invalid);
}

TEST(Signature, CanSignAndVerify)
{
    std::string data = "test message to sign";

    struct TestCase
    {
        mw::SignatureAlgorithm algo;
        std::string name;
    };

    std::vector<TestCase> test_cases = {
        {mw::SignatureAlgorithm::RSA_PSS_SHA512, "rsa_pss_sha512"},
        {mw::SignatureAlgorithm::RSA_V1_5_SHA256, "rsa_v1_5_sha256"},
        {mw::SignatureAlgorithm::ECDSA_P256_SHA256, "ecdsa_p256_sha256"},
        {mw::SignatureAlgorithm::ECDSA_P384_SHA384, "ecdsa_p384_sha384"},
        {mw::SignatureAlgorithm::ED25519, "ed25519"}};

    for (const auto& tc : test_cases)
    {
        SCOPED_TRACE(tc.name);
        auto pkey = generateKey(tc.algo);
        ASSERT_TRUE(pkey) << "Failed to generate key for " << tc.name;

        std::string priv_key_pem = getPrivateKeyPEM(pkey.get());
        std::string pub_key_pem = getPublicKeyPEM(pkey.get());

        mw::Crypto crypto;
        ASSIGN_OR_FAIL(auto signature, crypto.sign(tc.algo, priv_key_pem, data));

        ASSIGN_OR_FAIL(bool valid,
                       crypto.verifySignature(tc.algo, pub_key_pem, signature, data));
        EXPECT_TRUE(valid)
            << "Failed to verify signature generated by mw::sign for " << tc.name;
    }

    // HMAC test
    {
        std::string key(32, 'k');
        mw::SignatureAlgorithm algo = mw::SignatureAlgorithm::HMAC_SHA256;
        mw::Crypto crypto;
        ASSIGN_OR_FAIL(auto signature, crypto.sign(algo, key, data));
        ASSIGN_OR_FAIL(bool valid, crypto.verifySignature(algo, key, signature, data));
        EXPECT_TRUE(valid);
    }
}

TEST(Signature, CanGenerateAndVerifyEd25519KeyPair)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto key_pair, crypto.generateEd25519KeyPair());
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_FALSE(key_pair.private_key.empty());

    std::string data = "test message for generated key";

    // Sign using the generated private key
    ASSIGN_OR_FAIL(auto signature,
                   crypto.sign(mw::SignatureAlgorithm::ED25519,
                            key_pair.private_key, data));

    // Verify using the generated public key
    ASSIGN_OR_FAIL(bool valid,
                   crypto.verifySignature(mw::SignatureAlgorithm::ED25519,
                                       key_pair.public_key, signature, data));
    EXPECT_TRUE(valid);

    // Verify invalid signature
    signature[0] ^= 0xFF;
    ASSIGN_OR_FAIL(bool invalid,
                   crypto.verifySignature(mw::SignatureAlgorithm::ED25519,
                                       key_pair.public_key, signature, data));
    EXPECT_FALSE(invalid);
}
