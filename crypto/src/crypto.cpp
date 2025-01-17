#include <string>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>

#include "crypto.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace mw
{

SHA256Hasher::SHA256Hasher()
    : ctx(EVP_MD_CTX_new())
{
}

SHA256Hasher::~SHA256Hasher()
{
    EVP_MD_CTX_free(ctx);
}

E<std::string> SHA256Hasher::hashToHexStr(const std::string& bytes) const
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

    std::stringstream ss;
    for(unsigned int i = 0; i < hash_length; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

E<std::string> SHA256HalfHasher::hashToHexStr(const std::string& bytes) const
{
    ASSIGN_OR_RETURN(std::string hash, full_hasher.hashToHexStr(bytes));
    hash.resize(hash.size() / 2);
    return hash;
}

} // namespace mw
