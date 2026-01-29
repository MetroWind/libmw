#include <expected>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <memory>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "crypto.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace mw
{

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

namespace
{

std::string getOpenSSLError(const std::string& msg)
{
    return msg + ": " + ERR_error_string(ERR_get_error(), nullptr);
}

E<EVP_PKEY_ptr> loadKey(SignatureAlgorithm algo, const std::string& key)
{
    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);

    if (algo == SignatureAlgorithm::HMAC_SHA256)
    {
        pkey.reset(EVP_PKEY_new_mac_key(
            EVP_PKEY_HMAC, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()),
            static_cast<int>(key.size())));

        if (!pkey)
        {
            return std::unexpected(runtimeError("Failed to create HMAC key"));
        }
    }
    else
    {
        BIO_ptr bio(BIO_new_mem_buf(key.data(), static_cast<int>(key.size())),
                    BIO_free);
        if (!bio)
        {
            return std::unexpected(runtimeError("Failed to create key BIO"));
        }

        pkey.reset(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
        if (!pkey)
        {
            return std::unexpected(
                runtimeError(getOpenSSLError("Failed to load public key")));
        }
    }

    return pkey;
}

E<EVP_PKEY_ptr> loadPrivateKey(SignatureAlgorithm algo, const std::string& key)
{
    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);

    if (algo == SignatureAlgorithm::HMAC_SHA256)
    {
        pkey.reset(EVP_PKEY_new_mac_key(
            EVP_PKEY_HMAC, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()),
            static_cast<int>(key.size())));

        if (!pkey)
        {
            return std::unexpected(runtimeError("Failed to create HMAC key"));
        }
    }
    else
    {
        BIO_ptr bio(BIO_new_mem_buf(key.data(), static_cast<int>(key.size())),
                    BIO_free);
        if (!bio)
        {
            return std::unexpected(runtimeError("Failed to create key BIO"));
        }

        pkey.reset(
            PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
        if (!pkey)
        {
            return std::unexpected(
                runtimeError(getOpenSSLError("Failed to load private key")));
        }
    }

    return pkey;
}

const EVP_MD* getDigestMethod(SignatureAlgorithm algo)
{
    switch (algo)
    {
    case SignatureAlgorithm::RSA_PSS_SHA512:
        return EVP_sha512();
    case SignatureAlgorithm::RSA_V1_5_SHA256:
    case SignatureAlgorithm::HMAC_SHA256:
    case SignatureAlgorithm::ECDSA_P256_SHA256:
        return EVP_sha256();
    case SignatureAlgorithm::ECDSA_P384_SHA384:
        return EVP_sha384();
    case SignatureAlgorithm::ED25519:
        return nullptr;
    default:
        return nullptr;
    }
}

E<void> configureRSAPSS(EVP_PKEY_CTX* pkey_ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0)
    {
        return std::unexpected(
            runtimeError("Failed to set RSA PSS padding"));
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
    {
        return std::unexpected(
            runtimeError("Failed to set RSA PSS salt length"));
    }
    return {};
}

E<bool> verifyHMAC(EVP_PKEY* pkey, const std::string& data,
                   const std::vector<unsigned char>& signature)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr,
                           pkey) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestSignInit failed")));
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) <= 0)
    {
        return std::unexpected(
            runtimeError("EVP_DigestSign (length) failed"));
    }

    std::vector<unsigned char> computed_sig(sig_len);
    if (EVP_DigestSign(md_ctx.get(), computed_sig.data(), &sig_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) <= 0)
    {
        return std::unexpected(runtimeError("EVP_DigestSign failed"));
    }
    computed_sig.resize(sig_len);

    if (computed_sig.size() != signature.size())
    {
        return false;
    }

    return CRYPTO_memcmp(computed_sig.data(), signature.data(), sig_len) == 0;
}

E<bool> verifyAsymmetric(EVP_PKEY* pkey, SignatureAlgorithm algo,
                         const std::string& data,
                         const std::vector<unsigned char>& signature)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    const EVP_MD* md = getDigestMethod(algo);
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    if (EVP_DigestVerifyInit(md_ctx.get(), &pkey_ctx, md, nullptr, pkey) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestVerifyInit failed")));
    }

    if (algo == SignatureAlgorithm::RSA_PSS_SHA512)
    {
        if (auto result = configureRSAPSS(pkey_ctx); !result)
        {
            return std::unexpected(result.error());
        }
    }

    // Check parameters for EC/DSA
    if (EVP_PKEY_id(pkey) == EVP_PKEY_EC &&
        EVP_PKEY_missing_parameters(pkey))
    {
        return std::unexpected(runtimeError("Key missing parameters"));
    }

    int ret = 0;
    if (algo == SignatureAlgorithm::ED25519)
    {
        ret = EVP_DigestVerify(
            md_ctx.get(), signature.data(), signature.size(),
            reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }
    else
    {
        if (EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) <= 0)
        {
            return std::unexpected(
                runtimeError("EVP_DigestVerifyUpdate failed"));
        }
        ret = EVP_DigestVerifyFinal(md_ctx.get(), signature.data(),
                                    signature.size());
    }

    if (ret == 1)
    {
        return true;
    }
    else if (ret == 0)
    {
        return false;
    }
    else
    {
        // For some algorithms (like ECDSA), an invalid signature might return
        // -1 with an empty error queue. Treat this as a verification failure.
        if (ERR_peek_error() == 0)
        {
            return false;
        }

        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestVerify failed")));
    }
}

} // namespace

E<std::string> HasherInterface::hashToHexStr(const std::string& bytes) const
{
    ASSIGN_OR_RETURN(auto hash, this->hashToBytes(bytes));
    std::stringstream ss;
    for(auto byte : hash)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(byte);
    }
    return ss.str();
}

SHA256Hasher::SHA256Hasher()
    : ctx(EVP_MD_CTX_new())
{
}

SHA256Hasher::~SHA256Hasher()
{
    EVP_MD_CTX_free(ctx);
}

E<std::vector<unsigned char>> SHA256Hasher::hashToBytes(
    const std::string& bytes) const
{
    if(ctx == nullptr)
    {
        return std::unexpected(mw::runtimeError("Null EVP context"));
    }
    if(!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr))
    {
        return std::unexpected(mw::runtimeError("Failed to initialize hasher"));
    }
    if(!EVP_DigestUpdate(ctx, bytes.c_str(), bytes.length()))
    {
        return std::unexpected(mw::runtimeError("Failed to update hash"));
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;

    if(!EVP_DigestFinal_ex(ctx, hash, &hash_length))
    {
        return std::unexpected(mw::runtimeError("Failed to finalize hash"));
    }
    std::vector<unsigned char> result(hash, hash + hash_length);
    return result;
}

E<std::vector<unsigned char>> SHA256HalfHasher::hashToBytes(
    const std::string& bytes) const
{
    ASSIGN_OR_RETURN(auto hash, full_hasher.hashToBytes(bytes));
    hash.resize(hash.size() / 2);
    return hash;
}

E<bool> Crypto::verifySignature(SignatureAlgorithm algo, const std::string& key,
                                const std::vector<unsigned char>& signature,
                                const std::string& data)
{
    ERR_clear_error();
    ASSIGN_OR_RETURN(auto pkey, loadKey(algo, key));

    if (algo == SignatureAlgorithm::HMAC_SHA256)
    {
        return verifyHMAC(pkey.get(), data, signature);
    }

    return verifyAsymmetric(pkey.get(), algo, data, signature);
}

E<std::vector<unsigned char>> Crypto::sign(SignatureAlgorithm algo,
                                           const std::string& key,
                                           const std::string& data)
{
    ERR_clear_error();
    ASSIGN_OR_RETURN(auto pkey, loadPrivateKey(algo, key));

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    const EVP_MD* md = getDigestMethod(algo);
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    if (EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, md, nullptr, pkey.get()) <=
        0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestSignInit failed")));
    }

    if (algo == SignatureAlgorithm::RSA_PSS_SHA512)
    {
        if (auto result = configureRSAPSS(pkey_ctx); !result)
        {
            return std::unexpected(result.error());
        }
    }

    // Check parameters for EC/DSA
    if (EVP_PKEY_id(pkey.get()) == EVP_PKEY_EC &&
        EVP_PKEY_missing_parameters(pkey.get()))
    {
        return std::unexpected(runtimeError("Key missing parameters"));
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestSign (length) failed")));
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestSign failed")));
    }
    signature.resize(sig_len);

    return signature;
}

E<KeyPair> Crypto::generateKeyPair(KeyType type)
{
    int pkey_type = EVP_PKEY_ED25519;
    if (type == KeyType::RSA)
    {
        pkey_type = EVP_PKEY_RSA;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(pkey_type, nullptr);
    if (!ctx)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to create context")));
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx_ptr(
        ctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to init keygen")));
    }

    if (type == KeyType::RSA)
    {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        {
            return std::unexpected(
                runtimeError(getOpenSSLError("Failed to set RSA key bits")));
        }
    }

    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey_raw) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to generate key")));
    }
    EVP_PKEY_ptr pkey(pkey_raw, EVP_PKEY_free);

    BIO_ptr pub_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!pub_bio)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to create public key BIO")));
    }
    if (!PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()))
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to write public key")));
    }

    char* pub_data;
    long pub_len = BIO_get_mem_data(pub_bio.get(), &pub_data);
    std::string public_key(pub_data, pub_len);

    BIO_ptr priv_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!priv_bio)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to create private key BIO")));
    }
    if (!PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr,
                                  0, nullptr, nullptr))
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to write private key")));
    }

    char* priv_data;
    long priv_len = BIO_get_mem_data(priv_bio.get(), &priv_data);
    std::string private_key(priv_data, priv_len);

    return KeyPair{public_key, private_key};
}

} // namespace mw
