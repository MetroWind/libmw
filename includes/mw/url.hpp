#pragma once

#include <string>
#include <string_view>

#include <curl/curl.h>

#include "error.hpp"

namespace mw
{

class URL
{
public:
    URL() : url(nullptr) {}
    static E<URL> fromStr(const std::string& u);
    static E<URL> fromStr(const char* u);
    URL(const URL& rhs);
    URL(URL&& rhs);
    ~URL();

    URL& operator=(const URL& rhs);
    URL& operator=(URL&& rhs);

    // Returns empty string on error.
    std::string str() const;

    // Getters & setters. Getters returns empty values if error.
    // Setters do nothing if error.
    std::string host() const;
    URL& host(const char* value);
    std::string scheme() const;
    URL& scheme(const char* value);
    std::string port() const;
    URL& port(const char* value);
    std::string path() const;
    URL& path(const char* value);
    std::string query() const;
    URL& query(const char* value);
    std::string fragment() const;
    URL& fragment(const char* value);
    std::string user() const;
    URL& user(const char* value);
    std::string password() const;
    URL& password(const char* value);
    std::string zoneid() const;
    URL& zoneid(const char* value);

    // Append one or multiple segments to the URL, and return self.
    // This handles trailing and leading slashes correctly.
    URL& appendPath(std::string_view path);

    // Whether this object contains a valid URL
    bool valid() const { return url != nullptr; }

    static std::string encode(std::string_view s);
    static std::string decode(std::string_view s);

private:
    void init();
    CURLU* url;
};

} // namespace mw
