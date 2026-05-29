#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <functional>
#include <span>
#include <unordered_map>
#include <optional>
#include <utility>

#include <curl/curl.h>

#include "error.hpp"

namespace mw
{

// Callback invoked for each chunk of body data received during a
// streaming transfer. Return true to continue the transfer, or false
// to abort it. When aborted the streaming call returns a RuntimeError
// whose message equals HTTP_ABORTED_BY_CALLER.
using ChunkCallback =
    std::function<bool(std::span<const std::byte> chunk)>;

// Sentinel message used by the streaming variants when the user
// callback returns false. Tests and callers can compare against this
// to detect the "aborted by caller" case.
inline constexpr std::string_view HTTP_ABORTED_BY_CALLER =
    "transfer aborted by caller";

// Sentinel message used when a connection is refused by the address
// filter (see AddressPredicate). Tests and callers can compare against
// this to distinguish an SSRF/policy block from an ordinary network
// error.
inline constexpr std::string_view HTTP_BLOCKED_BY_POLICY =
    "connection blocked by address policy";

// Address family of a resolved destination, kept independent of
// <sys/socket.h> so callers do not need to include system headers.
enum class AddressFamily
{
    IPV4,
    IPV6,
};

// A resolved destination address, as seen right before a connection is
// made (after the library's own DNS resolution). This is what the
// address filter inspects.
//
// IPv4-mapped IPv6 addresses (e.g. "::ffff:127.0.0.1") are normalized
// to IPV4, with `address` holding the four embedded IPv4 bytes, so they
// cannot be used to bypass an IPv4-based blocklist.
struct SockAddr
{
    AddressFamily family = AddressFamily::IPV4;
    // Network-order address bytes: 4 bytes for IPV4, 16 for IPV6.
    std::vector<std::uint8_t> address;
    std::uint16_t port = 0;
};

// Predicate consulted for every connection the client is about to make,
// including each redirect hop, with the exact address it will connect
// to. Return true to allow the connection or false to block it. When a
// connection is blocked, the request fails with a RuntimeError whose
// message equals HTTP_BLOCKED_BY_POLICY.
//
// Because it sees the precise address the client resolved, there is no
// separate resolve step in the caller and therefore no DNS-rebinding
// (TOCTOU) window.
//
// The predicate runs inside the transfer; keep it cheap and
// non-throwing.
using AddressPredicate = std::function<bool(const SockAddr&)>;

struct HTTPRequest
{
    std::string url;
    std::string request_data;
    std::unordered_map<std::string, std::string> header;

    HTTPRequest() = default;
    explicit HTTPRequest(std::string_view uri) : url(uri) {}
    HTTPRequest& setPayload(std::string_view data);
    HTTPRequest& addHeader(std::string_view key, std::string_view value);
    HTTPRequest& setContentType(std::string_view type);
    bool operator==(const HTTPRequest& rhs) const = default;
};

struct HTTPResponse
{
    int status;
    std::vector<std::byte> payload;
    std::unordered_map<std::string, std::string> header;

    HTTPResponse() = default;
    HTTPResponse(int status_code, std::string_view payload_str);
    void clear();
    std::string_view payloadAsStr() const;
};

class HTTPSessionInterface
{
public:
    virtual ~HTTPSessionInterface() = default;
    E<const HTTPResponse*> get(const std::string& uri)
    {
        return this->get(HTTPRequest(uri));
    }
    virtual E<const HTTPResponse*> get(const HTTPRequest& req) = 0;
    virtual E<const HTTPResponse*> post(const HTTPRequest& req) = 0;

    // Streaming variants. The callback is invoked synchronously on
    // the calling thread for each body chunk as it arrives. Returning
    // false aborts the transfer. The returned HTTPResponse contains
    // the status and headers but its payload is left empty (the
    // caller consumed the body via on_chunk).
    virtual E<HTTPResponse> getStream(const HTTPRequest& req,
                                      ChunkCallback on_chunk) = 0;
    virtual E<HTTPResponse> postStream(const HTTPRequest& req,
                                       ChunkCallback on_chunk) = 0;

    // Return the timeout for data transfer. Default is no timeout.
    virtual std::chrono::duration<long> transferTimeout() const = 0;
    virtual E<void> transferTimeout(std::chrono::duration<long>) = 0;
    // Return the connection timeout. Default is 60 seconds.
    virtual std::chrono::duration<long> connectionTimeout() const = 0;
    virtual E<void> connectionTimeout(std::chrono::duration<long>) = 0;

    // Max download size.
    virtual long maxSize() const = 0;
    virtual E<void> maxSize(long) = 0;

    // Max number of redirections to follow, when redirect following is
    // enabled (see followRedirects()).
    virtual long maxRedirections() const = 0;
    virtual E<void> maxRedirections(long) = 0;

    // Whether to follow HTTP redirects. Default is true.
    virtual bool followRedirects() const = 0;
    virtual void followRedirects(bool) = 0;

    // Address filter consulted before each connection (including each
    // redirect hop). An empty predicate (the default) allows all
    // addresses. See AddressPredicate. The predicate must outlive the
    // requests it is used for.
    virtual const AddressPredicate& addressFilter() const = 0;
    virtual void addressFilter(AddressPredicate) = 0;

    // Restrict the protocols the client may use, as a comma-separated
    // list (e.g. "https" or "http,https"). An empty string (the
    // default) leaves the library default in place. `allowedProtocols`
    // applies to the initial request; `allowedRedirectProtocols`
    // applies to protocols a redirect may switch to.
    virtual E<void> allowedProtocols(std::string_view protocols) = 0;
    virtual E<void> allowedRedirectProtocols(std::string_view protocols) = 0;
};

// This class models an HTTP client using libcurl. Threads should not
// share session.
//
// Note that libcurl reuses HTTP connections by default. This may have
// some unwanted consequeces. For example, if you create a thread for
// an HTTP server, and make a query to that server using an object of
// this class, after that you stop the server and join the thread. The
// server may wait for a period of time before shutting down, instead
// of shutting down immediately. If you want the client object to drop
// connection immediately, you have to delete the object. The
// recommended way of doing this is to use RAII.
class HTTPSession : public virtual HTTPSessionInterface
{
public:
    HTTPSession();
    explicit HTTPSession(std::string_view socket_path);
    ~HTTPSession() override;
    HTTPSession(const HTTPSession&);
    HTTPSession& operator=(const HTTPSession&) = delete;

    using HTTPSessionInterface::get;
    // The returned pointer is garenteed to be non-null.
    E<const HTTPResponse*> get(const HTTPRequest& req) override;
    E<const HTTPResponse*> post(const HTTPRequest& req) override;

    // Streaming variants. See HTTPSessionInterface for semantics.
    // The body is delivered via on_chunk; HTTPResponse::payload is
    // not populated.
    E<HTTPResponse> getStream(const HTTPRequest& req,
                              ChunkCallback on_chunk) override;
    E<HTTPResponse> postStream(const HTTPRequest& req,
                               ChunkCallback on_chunk) override;

    std::chrono::duration<long> transferTimeout() const override;
    E<void> transferTimeout(std::chrono::duration<long> t) override;
    std::chrono::duration<long> connectionTimeout() const override;
    E<void> connectionTimeout(std::chrono::duration<long> t) override;
    long maxSize() const override { return max_size; }
    // Cannot exceed 2G.
    E<void> maxSize(long) override;
    long maxRedirections() const override { return max_redirections; }
    E<void> maxRedirections(long) override;

    bool followRedirects() const override { return follow_redirects; }
    void followRedirects(bool) override;

    const AddressPredicate& addressFilter() const override
    {
        return addr_filter;
    }
    void addressFilter(AddressPredicate pred) override
    {
        addr_filter = std::move(pred);
    }

    E<void> allowedProtocols(std::string_view protocols) override;
    E<void> allowedRedirectProtocols(std::string_view protocols) override;

private:
    CURL* handle = nullptr;
    HTTPResponse res;
    std::optional<std::string> socket = std::nullopt;
    long transfer_timeout_s = 0;
    long connection_timeout_s = 60;
    long max_size = 2147483648;
    long max_redirections = 0;
    bool follow_redirects = true;
    AddressPredicate addr_filter;
    std::string allowed_protocols;
    std::string allowed_redir_protocols;

    void prepareForNewRequest();
    // Install the open-socket callback for the current request. `ctx`
    // points to a per-request context (an opaque OpenSocketCtx) whose
    // `blocked` flag is set if the address filter refuses a connection.
    // Takes void* to keep this header free of libcurl socket types.
    void installAddressFilter(void* ctx);

    static size_t writeResponse(char *ptr, size_t size, size_t nmemb,
                                void *res_buffer);
    static size_t writeHeaders(char *buffer, size_t size, size_t nitems,
                               void *userdata);
    static size_t writeChunk(char *ptr, size_t size, size_t nmemb,
                             void *userdata);
};

} // namespace mw
