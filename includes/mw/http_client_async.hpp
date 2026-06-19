#pragma once

#include <chrono>
#include <memory>
#include <string_view>

#include "error.hpp"
#include "http_client.hpp"
#include "task.hpp"

namespace mw
{

class RequestAwaiter;

/// Coroutine-friendly HTTP client backed by one internal curl multi driver.
class HTTPSessionAsync
{
public:
    /// Create an async HTTP session.
    HTTPSessionAsync();

    /// Create an async HTTP session that connects through a Unix socket.
    explicit HTTPSessionAsync(std::string_view socket_path);

    /// Stop the driver thread and complete outstanding requests as cancelled.
    ~HTTPSessionAsync();

    HTTPSessionAsync(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync& operator=(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync(HTTPSessionAsync&&) = delete;
    HTTPSessionAsync& operator=(HTTPSessionAsync&&) = delete;

    /// Start an HTTP GET request and complete with a buffered response.
    Task<E<HTTPResponse>> get(HTTPRequest req);

    /// Start an HTTP POST request and complete with a buffered response.
    Task<E<HTTPResponse>> post(HTTPRequest req);

    /// Start an HTTP GET request and deliver chunks on the driver thread.
    Task<E<HTTPResponse>> getStream(HTTPRequest req, ChunkCallback on_chunk);

    /// Start an HTTP POST request and deliver chunks on the driver thread.
    Task<E<HTTPResponse>> postStream(HTTPRequest req, ChunkCallback on_chunk);

    /// Return the timeout for the full transfer. Zero means no timeout.
    std::chrono::duration<long> transferTimeout() const;

    /// Set the timeout for the full transfer. Zero means no timeout.
    E<void> transferTimeout(std::chrono::duration<long> t);

    /// Return the connection timeout.
    std::chrono::duration<long> connectionTimeout() const;

    /// Set the connection timeout.
    E<void> connectionTimeout(std::chrono::duration<long> t);

    /// Return the maximum accepted download size.
    long maxSize() const;

    /// Set the maximum accepted download size.
    E<void> maxSize(long s);

    /// Return the redirect cap.
    long maxRedirections() const;

    /// Set the redirect cap.
    E<void> maxRedirections(long n);

    /// Return whether redirects are followed.
    bool followRedirects() const;

    /// Set whether redirects are followed.
    void followRedirects(bool follow);

    /// Return the connect-time address filter.
    const AddressPredicate& addressFilter() const;

    /// Set the connect-time address filter.
    void addressFilter(AddressPredicate pred);

    /// Restrict protocols allowed for the initial request.
    E<void> allowedProtocols(std::string_view protocols);

    /// Restrict protocols allowed for redirects.
    E<void> allowedRedirectProtocols(std::string_view protocols);

private:
    friend class RequestAwaiter;

    class Impl;

    std::unique_ptr<Impl> impl;
};

} // namespace mw
