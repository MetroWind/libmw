#include <expected>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>

#include "crypto.hpp"
#include "error.hpp"
#include "utils.hpp"

namespace mw
{

E<std::string> HasherInterface::hashToHexStr(const std::string& bytes) const
{
    ASSIGN_OR_RETURN(auto hash, this->hashToBytes(bytes));
    std::stringstream ss;
    for(auto byte: hash)
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

E<std::vector<unsigned char>> SHA256Hasher::hashToBytes(const std::string& bytes) const
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

E<std::vector<unsigned char>> SHA256HalfHasher::hashToBytes(const std::string& bytes) const
{
    ASSIGN_OR_RETURN(auto hash, full_hasher.hashToBytes(bytes));
    hash.resize(hash.size() / 2);
    return hash;
}

} // namespace mw
