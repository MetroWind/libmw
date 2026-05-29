#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "http_client.hpp"
#include "error.hpp"

namespace mw
{

namespace
{

// Per-request state for the open-socket callback. Lives on the stack of
// the request method that installs it.
struct OpenSocketCtx
{
    // Null means no filtering (allow every connection).
    const AddressPredicate* filter;
    // Set by the callback when the filter refuses a connection.
    bool blocked;
};

// Translate the address libcurl is about to connect to into the public
// SockAddr, normalizing IPv4-mapped IPv6 to plain IPv4 so it cannot be
// used to slip past an IPv4 blocklist. Returns false for address
// families we do not understand.
bool toSockAddr(const struct curl_sockaddr* address, SockAddr& out)
{
    const struct sockaddr* addr = &address->addr;
    if(addr->sa_family == AF_INET)
    {
        const struct sockaddr_in* in =
            reinterpret_cast<const struct sockaddr_in*>(addr);
        out.family = AddressFamily::IPV4;
        out.address.resize(4);
        std::memcpy(out.address.data(), &in->sin_addr.s_addr, 4);
        out.port = ntohs(in->sin_port);
        return true;
    }
    if(addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6* in6 =
            reinterpret_cast<const struct sockaddr_in6*>(addr);
        const std::uint8_t* bytes =
            reinterpret_cast<const std::uint8_t*>(&in6->sin6_addr);
        out.port = ntohs(in6->sin6_port);
        // ::ffff:a.b.c.d -> normalize to IPv4.
        static constexpr std::uint8_t V4_MAPPED_PREFIX[12] =
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if(std::memcmp(bytes, V4_MAPPED_PREFIX, 12) == 0)
        {
            out.family = AddressFamily::IPV4;
            out.address.assign(bytes + 12, bytes + 16);
        }
        else
        {
            out.family = AddressFamily::IPV6;
            out.address.assign(bytes, bytes + 16);
        }
        return true;
    }
    return false;
}

// CURLOPT_OPENSOCKETFUNCTION. libcurl calls this after its own DNS
// resolution with the exact address it is about to connect to, for
// every connection including each redirect hop. Returning
// CURL_SOCKET_BAD aborts the connection. Must not throw.
curl_socket_t openSocketCallback(void* clientp, curlsocktype purpose,
                                 struct curl_sockaddr* address)
{
    OpenSocketCtx* ctx = static_cast<OpenSocketCtx*>(clientp);
    if(purpose == CURLSOCKTYPE_IPCXN && ctx != nullptr &&
       ctx->filter != nullptr && *ctx->filter)
    {
        SockAddr sa;
        if(toSockAddr(address, sa) && !(*ctx->filter)(sa))
        {
            ctx->blocked = true;
            return CURL_SOCKET_BAD;
        }
    }
    return ::socket(address->family, address->socktype, address->protocol);
}

} // namespace

HTTPRequest& HTTPRequest::setPayload(std::string_view data)
{
    request_data = data;
    return *this;
}

HTTPRequest& HTTPRequest::addHeader(std::string_view key, std::string_view value)
{
    header.emplace(key, value);
    return *this;
}

HTTPRequest& HTTPRequest::setContentType(std::string_view type)
{
    return addHeader("Content-Type", type);
}

HTTPResponse::HTTPResponse(int status_code, std::string_view payload_str)
        : status(status_code)
{
    std::transform(std::begin(payload_str), std::end(payload_str),
                   std::back_inserter(payload),
                   [](char c) { return std::byte(c); });
}

void HTTPResponse::clear()
{
    status = 0;
    payload.clear();
    header.clear();
}

std::string_view HTTPResponse::payloadAsStr() const
{
    return {reinterpret_cast<const char*>(payload.data()), payload.size()};
}

HTTPSession::HTTPSession()
{
    handle = curl_easy_init();
    res.payload.reserve(CURL_MAX_WRITE_SIZE);
}

HTTPSession::HTTPSession(std::string_view socket_path)
        : HTTPSession()
{
    socket = socket_path;
}

HTTPSession::~HTTPSession()
{
    if(handle != nullptr)
    {
        curl_easy_cleanup(handle);
    }
}

HTTPSession::HTTPSession(const HTTPSession& other)
{
    handle = curl_easy_duphandle(other.handle);
    socket = other.socket;
    transfer_timeout_s = other.transfer_timeout_s;
    connection_timeout_s = other.connection_timeout_s;
    max_size = other.max_size;
    max_redirections = other.max_redirections;
    follow_redirects = other.follow_redirects;
    addr_filter = other.addr_filter;
    allowed_protocols = other.allowed_protocols;
    allowed_redir_protocols = other.allowed_redir_protocols;
}

void HTTPSession::prepareForNewRequest()
{
    res.clear();
    // curl_easy_reset() clears every option, so the session settings
    // below must be re-applied for each request.
    curl_easy_reset(handle);
    if(socket.has_value())
    {
        curl_easy_setopt(handle, CURLOPT_UNIX_SOCKET_PATH, socket->c_str());
    }

    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, HTTPSession::writeResponse);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, HTTPSession::writeHeaders);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &res);

    curl_easy_setopt(handle, CURLOPT_TIMEOUT, transfer_timeout_s);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout_s);
    curl_easy_setopt(handle, CURLOPT_MAXFILESIZE, max_size);

    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION,
                     follow_redirects ? 1L : 0L);
    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, max_redirections);

    if(!allowed_protocols.empty())
    {
        curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR,
                         allowed_protocols.c_str());
    }
    if(!allowed_redir_protocols.empty())
    {
        curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR,
                         allowed_redir_protocols.c_str());
    }
}

void HTTPSession::installAddressFilter(void* ctx)
{
    // Only intercept socket creation when a filter is actually set, so
    // unfiltered sessions keep libcurl's default socket handling.
    if(!addr_filter)
    {
        return;
    }
    curl_easy_setopt(handle, CURLOPT_OPENSOCKETFUNCTION, openSocketCallback);
    curl_easy_setopt(handle, CURLOPT_OPENSOCKETDATA, ctx);
}

curl_slist* headersFromReq(const HTTPRequest& req)
{
    curl_slist* headers = nullptr;
    for(const auto& [key, value]: req.header)
    {
        headers = curl_slist_append(
            headers, std::format("{}: {}", key, value).c_str());
    }
    return headers;
}

E<const HTTPResponse*> HTTPSession::get(const HTTPRequest& req)
{
    prepareForNewRequest();
    OpenSocketCtx sock_ctx{addr_filter ? &addr_filter : nullptr, false};
    installAddressFilter(&sock_ctx);
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_slist* headers = headersFromReq(req);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    CURLcode code = curl_easy_perform(handle);
    curl_slist_free_all(headers);
    if(code == CURLE_OK)
    {
        return &res;
    }
    if(sock_ctx.blocked)
    {
        return std::unexpected(policyError(HTTP_BLOCKED_BY_POLICY));
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

E<const HTTPResponse*> HTTPSession::post(const HTTPRequest& req)
{
    prepareForNewRequest();
    OpenSocketCtx sock_ctx{addr_filter ? &addr_filter : nullptr, false};
    installAddressFilter(&sock_ctx);
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_slist* headers = headersFromReq(req);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req.request_data.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, req.request_data.size());

    CURLcode code = curl_easy_perform(handle);
    curl_slist_free_all(headers);
    if(code == CURLE_OK)
    {
        return &res;
    }
    if(sock_ctx.blocked)
    {
        return std::unexpected(policyError(HTTP_BLOCKED_BY_POLICY));
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

std::chrono::duration<long> HTTPSession::transferTimeout() const
{
    return std::chrono::duration<long>(transfer_timeout_s);
}

E<void> HTTPSession::transferTimeout(std::chrono::duration<long> t)
{
    CURLcode code = curl_easy_setopt(handle, CURLOPT_TIMEOUT, t.count());
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    transfer_timeout_s = t.count();
    return {};
}

std::chrono::duration<long> HTTPSession::connectionTimeout() const
{
    return std::chrono::duration<long>(connection_timeout_s);
}

E<void> HTTPSession::connectionTimeout(std::chrono::duration<long> t)
{
    CURLcode code = curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, t.count());
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    connection_timeout_s = t.count();
    return {};
}

E<void> HTTPSession::maxSize(long s)
{
    CURLcode code = curl_easy_setopt(handle, CURLOPT_MAXFILESIZE, s);
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    max_size = s;
    return {};
}

E<void> HTTPSession::maxRedirections(long n)
{
    CURLcode code = curl_easy_setopt(handle, CURLOPT_MAXREDIRS, n);
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    max_redirections = n;
    return {};
}

void HTTPSession::followRedirects(bool follow)
{
    follow_redirects = follow;
}

E<void> HTTPSession::allowedProtocols(std::string_view protocols)
{
    std::string value(protocols);
    CURLcode code = curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR,
                                     value.c_str());
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    allowed_protocols = std::move(value);
    return {};
}

E<void> HTTPSession::allowedRedirectProtocols(std::string_view protocols)
{
    std::string value(protocols);
    CURLcode code = curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR,
                                     value.c_str());
    if(code != CURLE_OK)
    {
        return std::unexpected(runtimeError(curl_easy_strerror(code)));
    }
    allowed_redir_protocols = std::move(value);
    return {};
}

size_t HTTPSession::writeResponse(char *ptr, size_t size, size_t nmemb,
                                  void *res)
{
    size_t realsize = size * nmemb;
    HTTPResponse* b = reinterpret_cast<HTTPResponse*>(res);
    // libcurl invokes this once per received chunk, so we must
    // append rather than overwrite. Otherwise responses larger than
    // CURL_MAX_WRITE_SIZE are silently truncated.
    size_t old_size = b->payload.size();
    b->payload.resize(old_size + realsize);
    std::memcpy(b->payload.data() + old_size, ptr, realsize);
    return realsize;
}

namespace
{

struct StreamCtx
{
    ChunkCallback* cb;
    bool aborted;
};

} // namespace

size_t HTTPSession::writeChunk(char *ptr, size_t size, size_t nmemb,
                               void *userdata)
{
    size_t realsize = size * nmemb;
    StreamCtx* ctx = reinterpret_cast<StreamCtx*>(userdata);
    std::span<const std::byte> chunk(
        reinterpret_cast<const std::byte*>(ptr), realsize);
    bool keep_going = (*ctx->cb)(chunk);
    if(!keep_going)
    {
        ctx->aborted = true;
        // Returning anything other than realsize signals an error to
        // libcurl, which surfaces as CURLE_WRITE_ERROR.
        return realsize == 0 ? 1 : realsize - 1;
    }
    return realsize;
}

E<HTTPResponse> HTTPSession::getStream(const HTTPRequest& req,
                                       ChunkCallback on_chunk)
{
    prepareForNewRequest();
    StreamCtx ctx{&on_chunk, false};
    OpenSocketCtx sock_ctx{addr_filter ? &addr_filter : nullptr, false};
    installAddressFilter(&sock_ctx);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, HTTPSession::writeChunk);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_slist* headers = headersFromReq(req);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    CURLcode code = curl_easy_perform(handle);
    curl_slist_free_all(headers);
    if(code == CURLE_OK)
    {
        HTTPResponse out;
        out.status = res.status;
        out.header = res.header;
        return out;
    }
    if(code == CURLE_WRITE_ERROR && ctx.aborted)
    {
        return std::unexpected(runtimeError(HTTP_ABORTED_BY_CALLER));
    }
    if(sock_ctx.blocked)
    {
        return std::unexpected(policyError(HTTP_BLOCKED_BY_POLICY));
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

E<HTTPResponse> HTTPSession::postStream(const HTTPRequest& req,
                                        ChunkCallback on_chunk)
{
    prepareForNewRequest();
    StreamCtx ctx{&on_chunk, false};
    OpenSocketCtx sock_ctx{addr_filter ? &addr_filter : nullptr, false};
    installAddressFilter(&sock_ctx);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, HTTPSession::writeChunk);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(handle, CURLOPT_URL, req.url.c_str());
    curl_slist* headers = headersFromReq(req);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req.request_data.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, req.request_data.size());
    CURLcode code = curl_easy_perform(handle);
    curl_slist_free_all(headers);
    if(code == CURLE_OK)
    {
        HTTPResponse out;
        out.status = res.status;
        out.header = res.header;
        return out;
    }
    if(code == CURLE_WRITE_ERROR && ctx.aborted)
    {
        return std::unexpected(runtimeError(HTTP_ABORTED_BY_CALLER));
    }
    if(sock_ctx.blocked)
    {
        return std::unexpected(policyError(HTTP_BLOCKED_BY_POLICY));
    }
    return std::unexpected(runtimeError(curl_easy_strerror(code)));
}

size_t HTTPSession::writeHeaders(char *buffer, [[maybe_unused]] size_t size,
                                 size_t nitems, void *userdata)
{
    // “size” is always 1. See
    // https://curl.se/libcurl/c/CURLOPT_HEADERFUNCTION.html.

    if(nitems == 0)
    {
        return 0;
    }

    std::string line(buffer, nitems);
    // Remove trailing newline if present.
    if(line.back() == '\n')
    {
        // HTTP lines are delimited by “\r\n”.
        line.pop_back();
        line.pop_back();
    }

    if(line.empty())
    {
        // This means we are at the end of the header section. For now
        // we don’t do anything.
        return nitems;
    }

    HTTPResponse* res = reinterpret_cast<HTTPResponse*>(userdata);
    if(line.starts_with("HTTP/"))
    {
        // This is a status line.
        size_t first_space_index = line.find_first_of(' ');
        if(first_space_index == std::string::npos)
        {
            return 0;
        }
        size_t second_space_index =
            line.find_first_of(' ', first_space_index + 1);
        if(second_space_index == std::string::npos)
        {
            return 0;
        }
        std::from_chars(line.data() + first_space_index + 1,
                        line.data() + second_space_index,
                        res->status);
    }
    else
    {
        size_t colon_index = line.find_first_of(':');

        std::string_view key(std::begin(line),
                             std::next(std::begin(line), colon_index));
        size_t i = colon_index + 1;
        while(line[i] == ' ') i++;
        std::string_view value(std::next(std::begin(line), i), std::end(line));
        res->header.emplace(key, value);
    }

    return nitems;
}

} // namespace mw
