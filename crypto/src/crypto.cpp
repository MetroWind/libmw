#include <expected>
#include <algorithm>
#include <array>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <memory>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>

#include "crypto.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace mw
{

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EVP_CIPHER_CTX_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using EVP_KDF_ptr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using EVP_KDF_CTX_ptr =
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

namespace
{

constexpr size_t GCM_IV_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;
constexpr size_t AES_256_KEY_LEN = 32;
constexpr int MIN_RSA_BITS = 2048;

enum class SignatureKeyKind
{
    RSA,
    EC,
    ED25519,
    HMAC
};

struct SignatureProfile
{
    SignatureKeyKind key_kind;
    const EVP_MD* digest;
    int ec_curve_nid;
    bool use_pss;
};

E<std::vector<unsigned char>> hash(const EVP_MD* digest,
                                  const std::string& bytes)
{
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!ctx)
    {
        return std::unexpected(runtimeError("Failed to create hash context"));
    }
    if(EVP_DigestInit_ex(ctx.get(), digest, nullptr) <= 0)
    {
        return std::unexpected(runtimeError("Failed to initialize hasher"));
    }
    if(EVP_DigestUpdate(ctx.get(), bytes.data(), bytes.size()) <= 0)
    {
        return std::unexpected(runtimeError("Failed to update hash"));
    }

    std::vector<unsigned char> result(
        static_cast<size_t>(EVP_MD_get_size(digest)));
    unsigned int hash_length = 0;
    if(EVP_DigestFinal_ex(ctx.get(), result.data(), &hash_length) <= 0)
    {
        return std::unexpected(runtimeError("Failed to finalize hash"));
    }
    result.resize(hash_length);
    return result;
}

std::string getOpenSSLError(const std::string& msg)
{
    return msg + ": " + ERR_error_string(ERR_get_error(), nullptr);
}

E<SignatureProfile> signatureProfile(SignatureAlgorithm algo)
{
    switch(algo)
    {
    case SignatureAlgorithm::RSA_PSS_SHA512:
        return SignatureProfile{SignatureKeyKind::RSA, EVP_sha512(),
                                NID_undef, true};
    case SignatureAlgorithm::RSA_V1_5_SHA256:
        return SignatureProfile{SignatureKeyKind::RSA, EVP_sha256(),
                                NID_undef, false};
    case SignatureAlgorithm::HMAC_SHA256:
        return SignatureProfile{SignatureKeyKind::HMAC, EVP_sha256(),
                                NID_undef, false};
    case SignatureAlgorithm::ECDSA_P256_SHA256:
        return SignatureProfile{SignatureKeyKind::EC, EVP_sha256(),
                                NID_X9_62_prime256v1, false};
    case SignatureAlgorithm::ECDSA_P384_SHA384:
        return SignatureProfile{SignatureKeyKind::EC, EVP_sha384(),
                                NID_secp384r1, false};
    case SignatureAlgorithm::ED25519:
        return SignatureProfile{SignatureKeyKind::ED25519, nullptr, NID_undef,
                                false};
    default:
        return std::unexpected(
            runtimeError("Unsupported signature algorithm"));
    }
}

E<EVP_PKEY_ptr> createHMACKey(const std::string& key)
{
    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);
    pkey.reset(EVP_PKEY_new_mac_key(
        EVP_PKEY_HMAC, nullptr,
        reinterpret_cast<const unsigned char*>(key.data()),
        static_cast<int>(key.size())));

    if (!pkey)
    {
        return std::unexpected(runtimeError("Failed to create HMAC key"));
    }

    return pkey;
}

E<EVP_PKEY_ptr> loadPublicKeyPEM(const std::string& key)
{
    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);
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

    return pkey;
}

E<EVP_PKEY_ptr> loadPrivateKeyPEM(const std::string& key)
{
    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);
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

    return pkey;
}

E<void> validateKeyType(EVP_PKEY* pkey, const SignatureProfile& profile)
{
    switch(profile.key_kind)
    {
    case SignatureKeyKind::RSA:
        // Check RSA-PSS first. Some providers expose a PSS-only key through
        // the general RSA name as well.
        if(EVP_PKEY_is_a(pkey, "RSA-PSS") == 1)
        {
            if(!profile.use_pss)
            {
                return std::unexpected(runtimeError(
                    "Incompatible key type for signature algorithm"));
            }
            return {};
        }
        if(EVP_PKEY_is_a(pkey, "RSA") == 1)
        {
            return {};
        }
        break;
    case SignatureKeyKind::EC:
        if(EVP_PKEY_is_a(pkey, "EC") == 1)
        {
            return {};
        }
        break;
    case SignatureKeyKind::ED25519:
        if(EVP_PKEY_is_a(pkey, "ED25519") == 1)
        {
            return {};
        }
        break;
    case SignatureKeyKind::HMAC:
        return {};
    default:
        break;
    }

    return std::unexpected(
        runtimeError("Incompatible key type for signature algorithm"));
}

E<void> validateRSAKey(EVP_PKEY* pkey)
{
    int bits = EVP_PKEY_get_bits(pkey);
    if(bits <= 0)
    {
        return std::unexpected(
            runtimeError("Failed to determine RSA key size"));
    }
    if(bits < MIN_RSA_BITS)
    {
        return std::unexpected(
            runtimeError("RSA key is smaller than 2048 bits"));
    }

    return {};
}

E<void> validateECKey(EVP_PKEY* pkey, const SignatureProfile& profile)
{
    std::array<char, 256> group_name{};
    size_t group_name_length = 0;
    if(EVP_PKEY_get_group_name(pkey, group_name.data(), group_name.size(),
                               &group_name_length) != 1 ||
       group_name_length >= group_name.size())
    {
        return std::unexpected(runtimeError("Failed to determine EC curve"));
    }

    const auto end = std::find(group_name.begin(), group_name.end(), '\0');
    if(end == group_name.end())
    {
        return std::unexpected(runtimeError("Failed to determine EC curve"));
    }

    const int curve_nid = OBJ_txt2nid(group_name.data());
    if(curve_nid != profile.ec_curve_nid)
    {
        return std::unexpected(
            runtimeError("Incompatible EC curve for signature algorithm"));
    }

    return {};
}

E<void> validatePublicKey(EVP_PKEY* pkey)
{
    EVP_PKEY_CTX_ptr pkey_ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr),
        EVP_PKEY_CTX_free);
    if(!pkey_ctx)
    {
        return std::unexpected(
            runtimeError("Failed to create public key validation context"));
    }

    const int result = EVP_PKEY_public_check(pkey_ctx.get());
    if(result == 1)
    {
        return {};
    }
    if(result == 0)
    {
        return std::unexpected(runtimeError("Invalid public key"));
    }

    return std::unexpected(runtimeError("Failed to validate public key"));
}

E<void> validatePrivateKey(EVP_PKEY* pkey)
{
    EVP_PKEY_CTX_ptr pkey_ctx(
        EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr),
        EVP_PKEY_CTX_free);
    if(!pkey_ctx)
    {
        return std::unexpected(
            runtimeError("Failed to create private key validation context"));
    }

    const int result = EVP_PKEY_pairwise_check(pkey_ctx.get());
    if(result == 1)
    {
        return {};
    }
    if(result == 0)
    {
        return std::unexpected(runtimeError("Invalid private key"));
    }

    return std::unexpected(runtimeError("Failed to validate private key"));
}

E<void> validateAsymmetricKey(EVP_PKEY* pkey,
                              const SignatureProfile& profile,
                              bool private_key)
{
    DO_OR_RETURN(validateKeyType(pkey, profile));

    switch(profile.key_kind)
    {
    case SignatureKeyKind::RSA:
        DO_OR_RETURN(validateRSAKey(pkey));
        break;
    case SignatureKeyKind::EC:
        DO_OR_RETURN(validateECKey(pkey, profile));
        break;
    case SignatureKeyKind::ED25519:
        break;
    case SignatureKeyKind::HMAC:
        return {};
    default:
        return std::unexpected(
            runtimeError("Incompatible key type for signature algorithm"));
    }

    if(private_key)
    {
        return validatePrivateKey(pkey);
    }
    return validatePublicKey(pkey);
}

E<void> configureSignatureContext(EVP_PKEY_CTX* pkey_ctx,
                                  const SignatureProfile& profile)
{
    if(profile.key_kind != SignatureKeyKind::RSA)
    {
        return {};
    }
    if(pkey_ctx == nullptr)
    {
        if(profile.use_pss)
        {
            return std::unexpected(runtimeError(
                "Incompatible RSA-PSS key restrictions"));
        }
        return std::unexpected(
            runtimeError("Failed to create RSA signature context"));
    }

    if(profile.use_pss)
    {
        const int padding_result =
            EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
        const int mgf1_result =
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, profile.digest);
        const int salt_length_result = EVP_PKEY_CTX_set_rsa_pss_saltlen(
            pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
        if(padding_result <= 0 || mgf1_result <= 0 ||
           salt_length_result <= 0)
        {
            return std::unexpected(runtimeError(
                "Incompatible RSA-PSS key restrictions"));
        }
        return {};
    }

    if(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
    {
        return std::unexpected(
            runtimeError("Failed to set RSA PKCS#1 v1.5 padding"));
    }

    return {};
}

E<const EVP_CIPHER*> encryptionCipher(EncryptionAlgorithm algo)
{
    switch(algo)
    {
    case EncryptionAlgorithm::AES_256_GCM:
        return EVP_aes_256_gcm();
    default:
        return std::unexpected(
            runtimeError("Unsupported encryption algorithm"));
    }
}

E<bool> verifyHMAC(EVP_PKEY* pkey, const SignatureProfile& profile,
                   const std::string& data,
                   const std::vector<unsigned char>& signature)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    if(EVP_DigestSignInit(md_ctx.get(), nullptr, profile.digest, nullptr,
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

E<bool> verifyAsymmetric(EVP_PKEY* pkey, const SignatureProfile& profile,
                         const std::string& data,
                         const std::vector<unsigned char>& signature)
{
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;

    if(EVP_DigestVerifyInit(md_ctx.get(), &pkey_ctx, profile.digest, nullptr,
                            pkey) <= 0)
    {
        if(profile.use_pss)
        {
            return std::unexpected(runtimeError(
                "Incompatible RSA-PSS key restrictions"));
        }
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestVerifyInit failed")));
    }

    if(auto result = configureSignatureContext(pkey_ctx, profile); !result)
    {
        return std::unexpected(result.error());
    }

    int ret = 0;
    if(profile.key_kind == SignatureKeyKind::ED25519)
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

E<std::vector<unsigned char>> SHA256Hasher::hashToBytes(
    const std::string& bytes) const
{
    return hash(EVP_sha256(), bytes);
}

E<std::vector<unsigned char>> SHA512Hasher::hashToBytes(
    const std::string& bytes) const
{
    return hash(EVP_sha512(), bytes);
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
    ASSIGN_OR_RETURN(auto profile, signatureProfile(algo));

    if(profile.key_kind == SignatureKeyKind::HMAC)
    {
        ASSIGN_OR_RETURN(auto pkey, createHMACKey(key));
        return verifyHMAC(pkey.get(), profile, data, signature);
    }

    ASSIGN_OR_RETURN(auto pkey, loadPublicKeyPEM(key));
    DO_OR_RETURN(validateAsymmetricKey(pkey.get(), profile, false));
    return verifyAsymmetric(pkey.get(), profile, data, signature);
}

E<std::vector<unsigned char>> Crypto::sign(SignatureAlgorithm algo,
                                           const std::string& key,
                                           const std::string& data)
{
    ERR_clear_error();
    ASSIGN_OR_RETURN(auto profile, signatureProfile(algo));

    EVP_PKEY_ptr pkey(nullptr, EVP_PKEY_free);
    if(profile.key_kind == SignatureKeyKind::HMAC)
    {
        ASSIGN_OR_RETURN(pkey, createHMACKey(key));
    }
    else
    {
        ASSIGN_OR_RETURN(pkey, loadPrivateKeyPEM(key));
        DO_OR_RETURN(validateAsymmetricKey(pkey.get(), profile, true));
    }

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!md_ctx)
    {
        return std::unexpected(runtimeError("Failed to create MD context"));
    }

    EVP_PKEY_CTX* pkey_ctx = nullptr;

    if(EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, profile.digest, nullptr,
                          pkey.get()) <= 0)
    {
        if(profile.use_pss)
        {
            return std::unexpected(runtimeError(
                "Incompatible RSA-PSS key restrictions"));
        }
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DigestSignInit failed")));
    }

    if(auto result = configureSignatureContext(pkey_ctx, profile); !result)
    {
        return std::unexpected(result.error());
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
    ERR_clear_error();

    int pkey_type;
    switch(type)
    {
    case KeyType::ED25519:
        pkey_type = EVP_PKEY_ED25519;
        break;
    case KeyType::RSA:
        pkey_type = EVP_PKEY_RSA;
        break;
    default:
        return std::unexpected(runtimeError("Unsupported key type"));
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

    char* pub_data = nullptr;
    long pub_len = BIO_get_mem_data(pub_bio.get(), &pub_data);
    if(pub_len <= 0 || pub_data == nullptr)
    {
        return std::unexpected(
            runtimeError("Failed to extract public key"));
    }
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

    char* priv_data = nullptr;
    long priv_len = BIO_get_mem_data(priv_bio.get(), &priv_data);
    if(priv_len <= 0 || priv_data == nullptr)
    {
        return std::unexpected(
            runtimeError("Failed to extract private key"));
    }
    std::string private_key(priv_data, priv_len);

    return KeyPair{public_key, private_key};
}

E<std::string> Crypto::encrypt(EncryptionAlgorithm algo, const std::string& key,
                               const std::string& clear_content)
{
    ERR_clear_error();
    ASSIGN_OR_RETURN(auto cipher, encryptionCipher(algo));

    if (key.size() != AES_256_KEY_LEN)
    {
        return std::unexpected(runtimeError("Invalid key length for AES-256"));
    }

    unsigned char iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to generate random IV")));
    }

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx)
    {
        return std::unexpected(
            runtimeError("Failed to create cipher context"));
    }

    if (EVP_EncryptInit_ex(
            ctx.get(), cipher, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), iv) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_EncryptInit_ex failed")));
    }

    std::vector<unsigned char> ciphertext(clear_content.size() +
                                          EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    if (EVP_EncryptUpdate(
            ctx.get(), ciphertext.data(), &len,
            reinterpret_cast<const unsigned char*>(clear_content.data()),
            static_cast<int>(clear_content.size())) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_EncryptUpdate failed")));
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_EncryptFinal_ex failed")));
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    unsigned char tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                            tag) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to get GCM tag")));
    }

    std::string result;
    result.reserve(GCM_IV_LEN + ciphertext_len + GCM_TAG_LEN);
    result.append(reinterpret_cast<char*>(iv), GCM_IV_LEN);
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    result.append(reinterpret_cast<char*>(tag), GCM_TAG_LEN);

    return result;
}

E<std::string> Crypto::decrypt(EncryptionAlgorithm algo, const std::string& key,
                               const std::string& encrypted_content)
{
    ERR_clear_error();
    ASSIGN_OR_RETURN(auto cipher, encryptionCipher(algo));

    if (key.size() != AES_256_KEY_LEN)
    {
        return std::unexpected(runtimeError("Invalid key length for AES-256"));
    }

    if (encrypted_content.size() < GCM_IV_LEN + GCM_TAG_LEN)
    {
        return std::unexpected(runtimeError("Ciphertext too short"));
    }

    const unsigned char* iv =
        reinterpret_cast<const unsigned char*>(encrypted_content.data());
    const unsigned char* ciphertext = iv + GCM_IV_LEN;
    size_t ciphertext_len = encrypted_content.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char* tag = ciphertext + ciphertext_len;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx)
    {
        return std::unexpected(
            runtimeError("Failed to create cipher context"));
    }

    if (EVP_DecryptInit_ex(
            ctx.get(), cipher, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()), iv) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DecryptInit_ex failed")));
    }

    std::vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext,
                          static_cast<int>(ciphertext_len)) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("EVP_DecryptUpdate failed")));
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                            const_cast<unsigned char*>(tag)) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to set GCM tag")));
    }

    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    if (ret > 0)
    {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return std::string(reinterpret_cast<char*>(plaintext.data()),
                           plaintext_len);
    }
    else
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Decryption/Authentication failed")));
    }
}

E<std::vector<unsigned char>> Crypto::deriveKeyArgon2id(
    const std::string& password, const std::string& salt, uint32_t iterations,
    uint32_t memory_kb, uint32_t parallelism, size_t key_length)
{
    ERR_clear_error();

    EVP_KDF_ptr kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);
    if(!kdf)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to fetch ARGON2ID KDF")));
    }

    EVP_KDF_CTX_ptr kctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
    if(!kctx)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("Failed to create KDF context")));
    }

    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(password.data()),
        password.size()));
    params.push_back(OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<char*>(salt.data()), salt.size()));
    params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,
                                                 &iterations));
    params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST,
                                                 &memory_kb));
    params.push_back(OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,
                                                 &parallelism));
    params.push_back(OSSL_PARAM_construct_end());

    std::vector<unsigned char> derived_key(key_length);
    if(EVP_KDF_derive(kctx.get(), derived_key.data(), derived_key.size(),
                       params.data()) <= 0)
    {
        return std::unexpected(
            runtimeError(getOpenSSLError("KDF derivation failed")));
    }

    return derived_key;
}

} // namespace mw
