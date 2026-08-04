#include <future>
#include <string>
#include <type_traits>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "crypto.hpp"
#include "test_utils.hpp"

using ::testing::ElementsAre;

static_assert(std::is_copy_constructible_v<mw::SHA256Hasher>);
static_assert(std::is_copy_assignable_v<mw::SHA256Hasher>);
static_assert(std::is_move_constructible_v<mw::SHA256Hasher>);
static_assert(std::is_move_assignable_v<mw::SHA256Hasher>);
static_assert(std::is_copy_constructible_v<mw::SHA512Hasher>);
static_assert(std::is_copy_assignable_v<mw::SHA512Hasher>);
static_assert(std::is_move_constructible_v<mw::SHA512Hasher>);
static_assert(std::is_move_assignable_v<mw::SHA512Hasher>);

namespace {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

std::string getPublicKeyPEM(EVP_PKEY* pkey)
{
    BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    if(!bio || PEM_write_bio_PUBKEY(bio.get(), pkey) <= 0)
    {
        return {};
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if(len <= 0 || data == nullptr)
    {
        return {};
    }
    return std::string(data, len);
}

std::string getPrivateKeyPEM(EVP_PKEY* pkey)
{
    BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    if(!bio ||
       PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr,
                                nullptr) <= 0)
    {
        return {};
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    if(len <= 0 || data == nullptr)
    {
        return {};
    }
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
    if(!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    if (algo == mw::SignatureAlgorithm::RSA_PSS_SHA512 ||
        algo == mw::SignatureAlgorithm::RSA_V1_5_SHA256) {
        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0)
        {
            return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
        }
    } else if (algo == mw::SignatureAlgorithm::ECDSA_P256_SHA256) {
        if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
               ctx.get(), NID_X9_62_prime256v1) <= 0)
        {
            return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
        }
    } else if (algo == mw::SignatureAlgorithm::ECDSA_P384_SHA384) {
        if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
               ctx.get(), NID_secp384r1) <= 0)
        {
            return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
        }
    }

    if(EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

EVP_PKEY_ptr generateRSAKey(int bits)
{
    EVP_PKEY_CTX_ptr ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if(!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
       EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY* pkey_raw = nullptr;
    if(EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

EVP_PKEY_ptr generateECKey(int curve_nid)
{
    EVP_PKEY_CTX_ptr ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if(!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
       EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curve_nid) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY* pkey_raw = nullptr;
    if(EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

EVP_PKEY_ptr generateEd25519Key()
{
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                         EVP_PKEY_CTX_free);
    if(!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY* pkey_raw = nullptr;
    if(EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

EVP_PKEY_ptr generatePSSKey(int bits, const EVP_MD* digest,
                            const EVP_MD* mgf1_digest, int salt_length)
{
    EVP_PKEY_CTX_ptr ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, nullptr), EVP_PKEY_CTX_free);
    if(!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
       EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    if(digest != nullptr &&
       EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.get(), digest) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    if(mgf1_digest != nullptr &&
       EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.get(), mgf1_digest) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    if(salt_length >= 0 &&
       EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.get(), salt_length) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    EVP_PKEY* pkey_raw = nullptr;
    if(EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

struct KeyMaterial
{
    std::string public_key;
    std::string private_key;
};

KeyMaterial getKeyMaterial(EVP_PKEY* pkey)
{
    return KeyMaterial{getPublicKeyPEM(pkey), getPrivateKeyPEM(pkey)};
}

template<typename T>
void expectError(const mw::E<T>& result, const std::string& message)
{
    ASSERT_FALSE(result.has_value());
    if(!result.has_value())
    {
        EXPECT_EQ(mw::errorMsg(result.error()), message);
    }
}

template<typename T>
void expectAnyError(const mw::E<T>& result)
{
    EXPECT_FALSE(result.has_value());
}

bool initializeTestSigningContext(EVP_MD_CTX* md_ctx, EVP_PKEY_CTX** pkey_ctx,
                                  mw::SignatureAlgorithm algo,
                                  const EVP_MD* digest, EVP_PKEY* pkey)
{
    if(EVP_DigestSignInit(md_ctx, pkey_ctx, digest, nullptr, pkey) <= 0)
    {
        return false;
    }
    if(algo == mw::SignatureAlgorithm::RSA_PSS_SHA512 && pkey_ctx == nullptr)
    {
        return false;
    }
    if(algo == mw::SignatureAlgorithm::RSA_PSS_SHA512 &&
       (EVP_PKEY_CTX_set_rsa_padding(*pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(*pkey_ctx, EVP_sha512()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(*pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <=
            0))
    {
        return false;
    }
    return true;
}

std::vector<unsigned char> sign(mw::SignatureAlgorithm algo, EVP_PKEY* pkey,
                                const std::string& data)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!md_ctx)
    {
        return {};
    }
    const EVP_MD* md = nullptr;
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    switch(algo)
    {
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

    if(!initializeTestSigningContext(md_ctx.get(), &pkey_ctx, algo, md, pkey))
    {
        return {};
    }
    size_t sig_len = 0;
    if(EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
                      reinterpret_cast<const unsigned char*>(data.data()),
                      data.size()) <= 0)
    {
        return {};
    }

    // Re-initialize for the actual signing
    if(EVP_MD_CTX_reset(md_ctx.get()) <= 0 ||
       !initializeTestSigningContext(md_ctx.get(), &pkey_ctx, algo, md, pkey))
    {
        return {};
    }

    std::vector<unsigned char> signature(sig_len);
    if(EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len,
                      reinterpret_cast<const unsigned char*>(data.data()),
                      data.size()) <= 0)
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
              "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af10"
              "7ee8f0");
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

TEST(Hash, CanHashSHA512)
{
    ASSIGN_OR_FAIL(auto hash, mw::SHA512Hasher().hashToBytes("aaa"));
    EXPECT_THAT(hash,
                ElementsAre(0xd6, 0xf6, 0x44, 0xb1, 0x98, 0x12, 0xe9, 0x7b,
                            0x5d, 0x87, 0x16, 0x58, 0xd6, 0xd3, 0x40, 0x0e,
                            0xcd, 0x47, 0x87, 0xfa, 0xeb, 0x9b, 0x89, 0x90,
                            0xc1, 0xe7, 0x60, 0x82, 0x88, 0x66, 0x4b, 0xe7,
                            0x72, 0x57, 0x10, 0x4a, 0x58, 0xd0, 0x33, 0xbc,
                            0xf1, 0xa0, 0xe0, 0x94, 0x5f, 0xf0, 0x64, 0x68,
                            0xeb, 0xe5, 0x3e, 0x2d, 0xff, 0x36, 0xe2, 0x48,
                            0x42, 0x4c, 0x72, 0x73, 0x11, 0x7d, 0xac, 0x09));

    ASSIGN_OR_FAIL(std::string result, mw::SHA512Hasher().hashToHexStr("aaa"));
    EXPECT_EQ(result,
              "d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be7"
              "7257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117d"
              "ac09");
}

TEST(Hash, InstancesMayBeUsedConcurrently)
{
    const mw::SHA256Hasher sha256_hasher;
    const mw::SHA512Hasher sha512_hasher;
    const mw::SHA256HalfHasher half_hasher;
    const std::string first_input = "concurrent input one";
    const std::string second_input = "concurrent input two";

    ASSIGN_OR_FAIL(auto first_sha256,
                   mw::SHA256Hasher().hashToBytes(first_input));
    ASSIGN_OR_FAIL(auto second_sha256,
                   mw::SHA256Hasher().hashToBytes(second_input));
    ASSIGN_OR_FAIL(auto first_sha512,
                   mw::SHA512Hasher().hashToBytes(first_input));
    ASSIGN_OR_FAIL(auto second_sha512,
                   mw::SHA512Hasher().hashToBytes(second_input));
    ASSIGN_OR_FAIL(auto first_half,
                   mw::SHA256HalfHasher().hashToBytes(first_input));
    ASSIGN_OR_FAIL(auto second_half,
                   mw::SHA256HalfHasher().hashToBytes(second_input));

    std::vector<std::future<bool>> results;
    constexpr size_t TASK_COUNT = 16;
    constexpr size_t HASHES_PER_TASK = 256;
    for(size_t task = 0; task < TASK_COUNT; ++task)
    {
        results.push_back(std::async(
            std::launch::async,
            [&, task]()
            {
                for(size_t iteration = 0; iteration < HASHES_PER_TASK;
                    ++iteration)
                {
                    const bool use_first = (task + iteration) % 2 == 0;
                    const std::string& input =
                        use_first ? first_input : second_input;
                    const auto& expected_sha256 =
                        use_first ? first_sha256 : second_sha256;
                    const auto& expected_sha512 =
                        use_first ? first_sha512 : second_sha512;
                    const auto& expected_half =
                        use_first ? first_half : second_half;

                    auto sha256 = sha256_hasher.hashToBytes(input);
                    auto sha512 = sha512_hasher.hashToBytes(input);
                    auto half = half_hasher.hashToBytes(input);
                    if(!sha256 || *sha256 != expected_sha256 ||
                       !sha512 || *sha512 != expected_sha512 ||
                       !half || *half != expected_half)
                    {
                        return false;
                    }
                }
                return true;
            }));
    }

    for(auto& result : results)
    {
        EXPECT_TRUE(result.get());
    }
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
        EXPECT_TRUE(valid)
            << "Failed to verify valid signature for " << tc.name;

        // Test invalid signature
        if (!signature.empty()) {
            signature[0] ^= 0xFF;
            ASSIGN_OR_FAIL(bool invalid, crypto.verifySignature(
                tc.algo, pub_key, signature, data));
            EXPECT_FALSE(invalid)
                << "Verified invalid signature for " << tc.name;
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
    ASSIGN_OR_FAIL(bool valid,
                   crypto.verifySignature(algo, key, signature, data));
    EXPECT_TRUE(valid);

    signature[0] ^= 0xFF;
    ASSIGN_OR_FAIL(bool invalid,
                   crypto.verifySignature(algo, key, signature, data));
    EXPECT_FALSE(invalid);
}

TEST(Signature, HMACKeyIsOpaqueBytes)
{
    std::string key("key\0with\0nulls", 14);
    const std::string data = "opaque HMAC key";
    mw::Crypto crypto;

    ASSIGN_OR_FAIL(auto signature,
                   crypto.sign(mw::SignatureAlgorithm::HMAC_SHA256, key,
                               data));
    ASSIGN_OR_FAIL(bool valid,
                   crypto.verifySignature(mw::SignatureAlgorithm::HMAC_SHA256,
                                           key, signature, data));
    EXPECT_TRUE(valid);
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
        ASSIGN_OR_FAIL(auto signature,
                       crypto.sign(tc.algo, priv_key_pem, data));

        ASSIGN_OR_FAIL(bool valid,
                       crypto.verifySignature(tc.algo, pub_key_pem, signature,
                                              data));
        EXPECT_TRUE(valid)
            << "Failed to verify signature generated by mw::sign for "
            << tc.name;
    }

    // HMAC test
    {
        std::string key(32, 'k');
        mw::SignatureAlgorithm algo = mw::SignatureAlgorithm::HMAC_SHA256;
        mw::Crypto crypto;
        ASSIGN_OR_FAIL(auto signature, crypto.sign(algo, key, data));
        ASSIGN_OR_FAIL(bool valid,
                       crypto.verifySignature(algo, key, signature, data));
        EXPECT_TRUE(valid);
    }
}

TEST(Signature, CanGenerateAndVerifyEd25519KeyPair)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto key_pair, crypto.generateKeyPair(mw::KeyType::ED25519));
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

TEST(Signature, CanGenerateAndVerifyRSAKeyPair)
{
    mw::Crypto crypto;
    ASSIGN_OR_FAIL(auto key_pair, crypto.generateKeyPair(mw::KeyType::RSA));
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_FALSE(key_pair.private_key.empty());

    std::string data = "test message for generated RSA key";

    // Sign using the generated private key (RSA_PSS_SHA512)
    ASSIGN_OR_FAIL(auto signature,
                   crypto.sign(mw::SignatureAlgorithm::RSA_PSS_SHA512,
                            key_pair.private_key, data));

    // Verify using the generated public key
    ASSIGN_OR_FAIL(bool valid,
                   crypto.verifySignature(
                       mw::SignatureAlgorithm::RSA_PSS_SHA512,
                       key_pair.public_key, signature, data));
    EXPECT_TRUE(valid);
}

TEST(Signature, AcceptsCompatibleRSAPSSKeys)
{
    struct TestCase
    {
        const EVP_MD* digest;
        const EVP_MD* mgf1_digest;
        int salt_length;
    };
    const std::vector<TestCase> test_cases = {
        {nullptr, nullptr, -1},
        {EVP_sha512(), EVP_sha512(), 64}};

    const std::string data = "RSA-PSS restriction test";
    mw::Crypto crypto;
    for(const auto& tc : test_cases)
    {
        auto pkey = generatePSSKey(2048, tc.digest, tc.mgf1_digest,
                                   tc.salt_length);
        ASSERT_TRUE(pkey);
        const auto key_material = getKeyMaterial(pkey.get());
        ASSERT_FALSE(key_material.public_key.empty());
        ASSERT_FALSE(key_material.private_key.empty());

        ASSIGN_OR_FAIL(auto signature,
                       crypto.sign(mw::SignatureAlgorithm::RSA_PSS_SHA512,
                                   key_material.private_key, data));
        ASSIGN_OR_FAIL(bool valid,
                       crypto.verifySignature(
                           mw::SignatureAlgorithm::RSA_PSS_SHA512,
                           key_material.public_key, signature, data));
        EXPECT_TRUE(valid);
    }
}

TEST(Signature, RejectsIncompatibleKeyTypes)
{
    auto rsa = generateRSAKey(2048);
    auto p256 = generateECKey(NID_X9_62_prime256v1);
    auto p384 = generateECKey(NID_secp384r1);
    auto ed25519 = generateEd25519Key();
    auto pss = generatePSSKey(2048, nullptr, nullptr, -1);
    ASSERT_TRUE(rsa);
    ASSERT_TRUE(p256);
    ASSERT_TRUE(p384);
    ASSERT_TRUE(ed25519);
    ASSERT_TRUE(pss);

    const KeyMaterial rsa_material = getKeyMaterial(rsa.get());
    const KeyMaterial p256_material = getKeyMaterial(p256.get());
    const KeyMaterial p384_material = getKeyMaterial(p384.get());
    const KeyMaterial ed25519_material = getKeyMaterial(ed25519.get());
    const KeyMaterial pss_material = getKeyMaterial(pss.get());

    struct TestCase
    {
        mw::SignatureAlgorithm algo;
        const KeyMaterial* key_material;
        const char* name;
    };
    const std::vector<TestCase> test_cases = {
        {mw::SignatureAlgorithm::RSA_PSS_SHA512, &p256_material, "RSA/EC"},
        {mw::SignatureAlgorithm::RSA_PSS_SHA512, &ed25519_material,
         "RSA/Ed25519"},
        {mw::SignatureAlgorithm::RSA_V1_5_SHA256, &p256_material, "RSA/EC"},
        {mw::SignatureAlgorithm::RSA_V1_5_SHA256, &ed25519_material,
         "RSA/Ed25519"},
        {mw::SignatureAlgorithm::ECDSA_P256_SHA256, &rsa_material, "EC/RSA"},
        {mw::SignatureAlgorithm::ECDSA_P256_SHA256, &ed25519_material,
         "EC/Ed25519"},
        {mw::SignatureAlgorithm::ECDSA_P384_SHA384, &rsa_material, "EC/RSA"},
        {mw::SignatureAlgorithm::ECDSA_P384_SHA384, &ed25519_material,
         "EC/Ed25519"},
        {mw::SignatureAlgorithm::ED25519, &rsa_material, "Ed25519/RSA"},
        {mw::SignatureAlgorithm::ED25519, &p256_material, "Ed25519/EC"},
        {mw::SignatureAlgorithm::RSA_V1_5_SHA256, &pss_material,
         "RSA-v1.5/RSA-PSS"}};

    const std::string data = "incompatible key type";
    mw::Crypto crypto;
    for(const auto& tc : test_cases)
    {
        SCOPED_TRACE(tc.name);
        expectError(crypto.sign(tc.algo, tc.key_material->private_key, data),
                    "Incompatible key type for signature algorithm");
        expectError(crypto.verifySignature(tc.algo,
                                           tc.key_material->public_key, {},
                                           data),
                    "Incompatible key type for signature algorithm");
    }
}

TEST(Signature, RejectsIncompatibleECCurves)
{
    auto p256 = generateECKey(NID_X9_62_prime256v1);
    auto p384 = generateECKey(NID_secp384r1);
    ASSERT_TRUE(p256);
    ASSERT_TRUE(p384);
    const KeyMaterial p256_material = getKeyMaterial(p256.get());
    const KeyMaterial p384_material = getKeyMaterial(p384.get());

    const std::string data = "incompatible EC curve";
    mw::Crypto crypto;

    const auto p256_signature =
        sign(mw::SignatureAlgorithm::ECDSA_P256_SHA256, p256.get(), data);
    const auto p384_signature =
        sign(mw::SignatureAlgorithm::ECDSA_P384_SHA384, p384.get(), data);
    ASSERT_FALSE(p256_signature.empty());
    ASSERT_FALSE(p384_signature.empty());

    expectError(crypto.sign(mw::SignatureAlgorithm::ECDSA_P256_SHA256,
                            p384_material.private_key, data),
                "Incompatible EC curve for signature algorithm");
    expectError(crypto.verifySignature(
                    mw::SignatureAlgorithm::ECDSA_P256_SHA256,
                    p384_material.public_key, p384_signature, data),
                "Incompatible EC curve for signature algorithm");
    expectError(crypto.sign(mw::SignatureAlgorithm::ECDSA_P384_SHA384,
                            p256_material.private_key, data),
                "Incompatible EC curve for signature algorithm");
    expectError(crypto.verifySignature(
                    mw::SignatureAlgorithm::ECDSA_P384_SHA384,
                    p256_material.public_key, p256_signature, data),
                "Incompatible EC curve for signature algorithm");
}

TEST(Signature, RejectsWeakRSAKeys)
{
    auto weak_rsa = generateRSAKey(1024);
    ASSERT_TRUE(weak_rsa);
    const auto key_material = getKeyMaterial(weak_rsa.get());
    ASSERT_FALSE(key_material.public_key.empty());
    ASSERT_FALSE(key_material.private_key.empty());

    const std::vector<mw::SignatureAlgorithm> algorithms = {
        mw::SignatureAlgorithm::RSA_PSS_SHA512,
        mw::SignatureAlgorithm::RSA_V1_5_SHA256};
    mw::Crypto crypto;
    for(const auto algo : algorithms)
    {
        expectError(crypto.sign(algo, key_material.private_key, "weak RSA"),
                    "RSA key is smaller than 2048 bits");
        expectError(crypto.verifySignature(algo, key_material.public_key, {},
                                            "weak RSA"),
                    "RSA key is smaller than 2048 bits");
    }
}

TEST(Signature, RejectsPSSKeysWithIncompatibleRestrictions)
{
    struct TestCase
    {
        const EVP_MD* digest;
        const EVP_MD* mgf1_digest;
        int salt_length;
    };
    const std::vector<TestCase> test_cases = {
        {EVP_sha256(), nullptr, -1},
        {nullptr, EVP_sha256(), -1},
        {nullptr, nullptr, 65}};

    const std::string data = "incompatible RSA-PSS restrictions";
    mw::Crypto crypto;
    for(const auto& tc : test_cases)
    {
        auto pkey = generatePSSKey(2048, tc.digest, tc.mgf1_digest,
                                   tc.salt_length);
        ASSERT_TRUE(pkey);
        const auto key_material = getKeyMaterial(pkey.get());
        ASSERT_FALSE(key_material.public_key.empty());
        ASSERT_FALSE(key_material.private_key.empty());

        expectError(crypto.sign(mw::SignatureAlgorithm::RSA_PSS_SHA512,
                                key_material.private_key, data),
                    "Incompatible RSA-PSS key restrictions");
        expectError(crypto.verifySignature(
                        mw::SignatureAlgorithm::RSA_PSS_SHA512,
                        key_material.public_key, {}, data),
                    "Incompatible RSA-PSS key restrictions");
    }
}

TEST(Signature, RejectsMalformedPEMAndPublicSigningKeys)
{
    auto rsa = generateRSAKey(2048);
    auto p256 = generateECKey(NID_X9_62_prime256v1);
    auto p384 = generateECKey(NID_secp384r1);
    auto ed25519 = generateEd25519Key();
    ASSERT_TRUE(rsa);
    ASSERT_TRUE(p256);
    ASSERT_TRUE(p384);
    ASSERT_TRUE(ed25519);

    struct TestCase
    {
        mw::SignatureAlgorithm algo;
        const KeyMaterial* key_material;
    };
    const KeyMaterial rsa_material = getKeyMaterial(rsa.get());
    const KeyMaterial p256_material = getKeyMaterial(p256.get());
    const KeyMaterial p384_material = getKeyMaterial(p384.get());
    const KeyMaterial ed25519_material = getKeyMaterial(ed25519.get());
    const std::vector<TestCase> test_cases = {
        {mw::SignatureAlgorithm::RSA_PSS_SHA512, &rsa_material},
        {mw::SignatureAlgorithm::ECDSA_P256_SHA256, &p256_material},
        {mw::SignatureAlgorithm::ECDSA_P384_SHA384, &p384_material},
        {mw::SignatureAlgorithm::ED25519, &ed25519_material}};
    const std::vector<std::string> malformed_keys = {
        "", "not a PEM key", "-----BEGIN PUBLIC KEY-----\ninvalid"};

    mw::Crypto crypto;
    for(const auto& tc : test_cases)
    {
        for(const auto& malformed_key : malformed_keys)
        {
            expectAnyError(crypto.sign(tc.algo, malformed_key, "malformed"));
            expectAnyError(
                crypto.verifySignature(tc.algo, malformed_key, {},
                                       "malformed"));
        }

        expectAnyError(crypto.sign(tc.algo, tc.key_material->public_key,
                                   "public key cannot sign"));
    }

    expectAnyError(crypto.sign(mw::SignatureAlgorithm::ECDSA_P384_SHA384,
                               p256_material.public_key, "wrong curve"));
}

TEST(Signature, RejectsUnknownSignatureAlgorithm)
{
    constexpr auto unknown =
        static_cast<mw::SignatureAlgorithm>(-1);
    mw::Crypto crypto;

    expectError(crypto.sign(unknown, "not a PEM key", "unknown"),
                "Unsupported signature algorithm");
    expectError(crypto.verifySignature(unknown, "not a PEM key", {}, "unknown"),
                "Unsupported signature algorithm");
}

TEST(Encryption, CanEncryptAndDecrypt)
{
    mw::Crypto crypto;
    std::string key(32, 'k');
    std::string plaintext = "Secret message";
    mw::EncryptionAlgorithm algo = mw::EncryptionAlgorithm::AES_256_GCM;

    ASSIGN_OR_FAIL(std::string ciphertext,
                   crypto.encrypt(algo, key, plaintext));
    EXPECT_NE(ciphertext, plaintext);
    EXPECT_GT(ciphertext.size(), plaintext.size());

    ASSIGN_OR_FAIL(std::string decrypted,
                   crypto.decrypt(algo, key, ciphertext));
    EXPECT_EQ(decrypted, plaintext);
}

TEST(Encryption, ReturnsErrorOnInvalidKeyLength)
{
    mw::Crypto crypto;
    std::string key(31, 'k');
    std::string plaintext = "Secret message";
    mw::EncryptionAlgorithm algo = mw::EncryptionAlgorithm::AES_256_GCM;

    auto result = crypto.encrypt(algo, key, plaintext);
    EXPECT_FALSE(result);

    std::string valid_key(32, 'k');
    ASSIGN_OR_FAIL(std::string ciphertext,
                   crypto.encrypt(algo, valid_key, plaintext));

    auto decrypt_result = crypto.decrypt(algo, key, ciphertext);
    EXPECT_FALSE(decrypt_result);
}

TEST(Encryption, ReturnsErrorOnTamperedCiphertext)
{
    mw::Crypto crypto;
    std::string key(32, 'k');
    std::string plaintext = "Secret message";
    mw::EncryptionAlgorithm algo = mw::EncryptionAlgorithm::AES_256_GCM;

    ASSIGN_OR_FAIL(std::string ciphertext,
                   crypto.encrypt(algo, key, plaintext));

    // Tamper with the ciphertext (last byte of tag)
    ciphertext.back() ^= 0xFF;

    auto result = crypto.decrypt(algo, key, ciphertext);
    EXPECT_FALSE(result);
}

TEST(Encryption, ReturnsErrorOnEmptyCiphertext)
{
    mw::Crypto crypto;
    std::string key(32, 'k');
    mw::EncryptionAlgorithm algo = mw::EncryptionAlgorithm::AES_256_GCM;

    auto result = crypto.decrypt(algo, key, "");
    EXPECT_FALSE(result);
}

TEST(Encryption, RejectsUnknownEncryptionAlgorithm)
{
    constexpr auto unknown =
        static_cast<mw::EncryptionAlgorithm>(-1);
    const std::string key(32, 'k');
    mw::Crypto crypto;

    ASSIGN_OR_FAIL(auto ciphertext,
                   crypto.encrypt(mw::EncryptionAlgorithm::AES_256_GCM, key,
                                  "valid input"));
    expectError(crypto.encrypt(unknown, key, "valid input"),
                "Unsupported encryption algorithm");
    expectError(crypto.decrypt(unknown, key, ciphertext),
                "Unsupported encryption algorithm");
}

TEST(Signature, RejectsUnknownKeyType)
{
    constexpr auto unknown = static_cast<mw::KeyType>(-1);
    mw::Crypto crypto;

    expectError(crypto.generateKeyPair(unknown), "Unsupported key type");
}

TEST(KDF, Argon2idConsistency)
{
    mw::Crypto crypto;
    std::string password = "password";
    std::string salt = "somesalt12345678";
    uint32_t iterations = 2;
    uint32_t memory_kb = 4096;
    uint32_t parallelism = 1;
    size_t key_length = 32;

    ASSIGN_OR_FAIL(auto key1, crypto.deriveKeyArgon2id(
                                  password, salt, iterations, memory_kb,
                                  parallelism, key_length));
    ASSIGN_OR_FAIL(auto key2, crypto.deriveKeyArgon2id(
                                  password, salt, iterations, memory_kb,
                                  parallelism, key_length));

    EXPECT_EQ(key1, key2);
    EXPECT_EQ(key1.size(), key_length);
}

TEST(KDF, Argon2idDistinction)
{
    mw::Crypto crypto;
    std::string password = "password";
    std::string salt = "somesalt12345678";
    uint32_t iterations = 2;
    uint32_t memory_kb = 4096;
    uint32_t parallelism = 1;
    size_t key_length = 32;

    ASSIGN_OR_FAIL(auto base_key, crypto.deriveKeyArgon2id(
                                      password, salt, iterations, memory_kb,
                                      parallelism, key_length));

    // Different password
    ASSIGN_OR_FAIL(auto diff_pass, crypto.deriveKeyArgon2id(
                                       "different", salt, iterations, memory_kb,
                                       parallelism, key_length));
    EXPECT_NE(base_key, diff_pass);

    // Different salt
    ASSIGN_OR_FAIL(auto diff_salt, crypto.deriveKeyArgon2id(
                                       password, "diffsalt12345678", iterations,
                                       memory_kb, parallelism, key_length));
    EXPECT_NE(base_key, diff_salt);

    // Different iterations
    ASSIGN_OR_FAIL(auto diff_iter, crypto.deriveKeyArgon2id(
                                       password, salt, iterations + 1,
                                       memory_kb, parallelism, key_length));
    EXPECT_NE(base_key, diff_iter);

    // Different memory
    ASSIGN_OR_FAIL(auto diff_mem, crypto.deriveKeyArgon2id(
                                      password, salt, iterations,
                                      memory_kb * 2, parallelism, key_length));
    EXPECT_NE(base_key, diff_mem);
}

TEST(KDF, Argon2idVariableLength)
{
    mw::Crypto crypto;
    std::string password = "password";
    std::string salt = "somesalt12345678";
    uint32_t iterations = 2;
    uint32_t memory_kb = 4096;
    uint32_t parallelism = 1;

    ASSIGN_OR_FAIL(auto key16, crypto.deriveKeyArgon2id(
                                   password, salt, iterations, memory_kb,
                                   parallelism, 16));
    EXPECT_EQ(key16.size(), 16);

    ASSIGN_OR_FAIL(auto key64, crypto.deriveKeyArgon2id(
                                   password, salt, iterations, memory_kb,
                                   parallelism, 64));
    EXPECT_EQ(key64.size(), 64);

    EXPECT_NE(std::vector<unsigned char>(key64.begin(), key64.begin() + 16),
              key16);
}
