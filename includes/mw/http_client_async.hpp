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

/// Interface for coroutine-friendly HTTP clients.
class HTTPSessionAsyncInterface
{
public:
    /// Destroy the async HTTP session interface.
    virtual ~HTTPSessionAsyncInterface() = default;

    /// Start an HTTP GET request and complete with a buffered response.
    virtual Task<E<HTTPResponse>> get(HTTPRequest req) = 0;

    /// Start an HTTP POST request and complete with a buffered response.
    virtual Task<E<HTTPResponse>> post(HTTPRequest req) = 0;

    /// Start an HTTP GET request and deliver chunks on the driver thread.
    virtual Task<E<HTTPResponse>> getStream(HTTPRequest req,
                                            ChunkCallback on_chunk) = 0;

    /// Start an HTTP POST request and deliver chunks on the driver thread.
    virtual Task<E<HTTPResponse>> postStream(HTTPRequest req,
                                             ChunkCallback on_chunk) = 0;

    /// Return the timeout for the full transfer. Zero means no timeout.
    virtual std::chrono::duration<long> transferTimeout() const = 0;

    /// Set the timeout for the full transfer. Zero means no timeout.
    virtual E<void> transferTimeout(std::chrono::duration<long> t) = 0;

    /// Return the connection timeout.
    virtual std::chrono::duration<long> connectionTimeout() const = 0;

    /// Set the connection timeout.
    virtual E<void> connectionTimeout(std::chrono::duration<long> t) = 0;

    /// Return the maximum accepted download size.
    virtual long maxSize() const = 0;

    /// Set the maximum accepted download size.
    virtual E<void> maxSize(long s) = 0;

    /// Return the redirect cap.
    virtual long maxRedirections() const = 0;

    /// Set the redirect cap.
    virtual E<void> maxRedirections(long n) = 0;

    /// Return whether redirects are followed.
    virtual bool followRedirects() const = 0;

    /// Set whether redirects are followed.
    virtual void followRedirects(bool follow) = 0;

    /// Return the connect-time address filter.
    virtual const AddressPredicate& addressFilter() const = 0;

    /// Set the connect-time address filter.
    virtual void addressFilter(AddressPredicate pred) = 0;

    /// Restrict protocols allowed for the initial request.
    virtual E<void> allowedProtocols(std::string_view protocols) = 0;

    /// Restrict protocols allowed for redirects.
    virtual E<void> allowedRedirectProtocols(
        std::string_view protocols) = 0;
};

/// Coroutine-friendly HTTP client backed by one internal curl multi driver.
class HTTPSessionAsync : public HTTPSessionAsyncInterface
{
public:
    /// Create an async HTTP session.
    HTTPSessionAsync();

    /// Create an async HTTP session that connects through a Unix socket.
    explicit HTTPSessionAsync(std::string_view socket_path);

    /// Stop the driver thread and complete outstanding requests as cancelled.
    ~HTTPSessionAsync() override;

    HTTPSessionAsync(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync& operator=(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync(HTTPSessionAsync&&) = delete;
    HTTPSessionAsync& operator=(HTTPSessionAsync&&) = delete;

    /// Start an HTTP GET request and complete with a buffered response.
    Task<E<HTTPResponse>> get(HTTPRequest req) override;

    /// Start an HTTP POST request and complete with a buffered response.
    Task<E<HTTPResponse>> post(HTTPRequest req) override;

    /// Start an HTTP GET request and deliver chunks on the driver thread.
    Task<E<HTTPResponse>> getStream(HTTPRequest req,
                                    ChunkCallback on_chunk) override;

    /// Start an HTTP POST request and deliver chunks on the driver thread.
    Task<E<HTTPResponse>> postStream(HTTPRequest req,
                                     ChunkCallback on_chunk) override;

    /// Return the timeout for the full transfer. Zero means no timeout.
    std::chrono::duration<long> transferTimeout() const override;

    /// Set the timeout for the full transfer. Zero means no timeout.
    E<void> transferTimeout(std::chrono::duration<long> t) override;

    /// Return the connection timeout.
    std::chrono::duration<long> connectionTimeout() const override;

    /// Set the connection timeout.
    E<void> connectionTimeout(std::chrono::duration<long> t) override;

    /// Return the maximum accepted download size.
    long maxSize() const override;

    /// Set the maximum accepted download size.
    E<void> maxSize(long s) override;

    /// Return the redirect cap.
    long maxRedirections() const override;

    /// Set the redirect cap.
    E<void> maxRedirections(long n) override;

    /// Return whether redirects are followed.
    bool followRedirects() const override;

    /// Set whether redirects are followed.
    void followRedirects(bool follow) override;

    /// Return the connect-time address filter.
    const AddressPredicate& addressFilter() const override;

    /// Set the connect-time address filter.
    void addressFilter(AddressPredicate pred) override;

    /// Restrict protocols allowed for the initial request.
    E<void> allowedProtocols(std::string_view protocols) override;

    /// Restrict protocols allowed for redirects.
    E<void> allowedRedirectProtocols(std::string_view protocols) override;

private:
    friend class RequestAwaiter;

    class Impl;

    std::unique_ptr<Impl> impl;
};

} // namespace mw
