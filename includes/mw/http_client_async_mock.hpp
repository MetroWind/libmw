#pragma once

#include <chrono>
#include <string_view>
#include <utility>

#include <gmock/gmock.h>

#include "http_client_async.hpp"

namespace mw
{

/// Google Mock test double for HTTPSessionAsync.
class HTTPSessionAsyncMock
{
public:
    /// Destroy the mock session.
    ~HTTPSessionAsyncMock() = default;

    /// Create a task that immediately completes with result.
    static Task<E<HTTPResponse>> complete(E<HTTPResponse> result)
    {
        co_return std::move(result);
    }

    /// Start an HTTP GET request and complete with a buffered response.
    MOCK_METHOD((Task<E<HTTPResponse>>), get, (HTTPRequest req));

    /// Start an HTTP POST request and complete with a buffered response.
    MOCK_METHOD((Task<E<HTTPResponse>>), post, (HTTPRequest req));

    /// Start an HTTP GET request and deliver chunks on the driver thread.
    MOCK_METHOD((Task<E<HTTPResponse>>), getStream,
                (HTTPRequest req, ChunkCallback on_chunk));

    /// Start an HTTP POST request and deliver chunks on the driver thread.
    MOCK_METHOD((Task<E<HTTPResponse>>), postStream,
                (HTTPRequest req, ChunkCallback on_chunk));

    /// Return the timeout for the full transfer. Zero means no timeout.
    MOCK_METHOD(std::chrono::duration<long>, transferTimeout, (), (const));

    /// Set the timeout for the full transfer. Zero means no timeout.
    MOCK_METHOD(E<void>, transferTimeout, (std::chrono::duration<long>));

    /// Return the connection timeout.
    MOCK_METHOD(std::chrono::duration<long>, connectionTimeout, (), (const));

    /// Set the connection timeout.
    MOCK_METHOD(E<void>, connectionTimeout, (std::chrono::duration<long>));

    /// Return the maximum accepted download size.
    MOCK_METHOD(long, maxSize, (), (const));

    /// Set the maximum accepted download size.
    MOCK_METHOD(E<void>, maxSize, (long));

    /// Return the redirect cap.
    MOCK_METHOD(long, maxRedirections, (), (const));

    /// Set the redirect cap.
    MOCK_METHOD(E<void>, maxRedirections, (long));

    /// Return whether redirects are followed.
    MOCK_METHOD(bool, followRedirects, (), (const));

    /// Set whether redirects are followed.
    MOCK_METHOD(void, followRedirects, (bool));

    /// Return the connect-time address filter.
    MOCK_METHOD(const AddressPredicate&, addressFilter, (), (const));

    /// Set the connect-time address filter.
    MOCK_METHOD(void, addressFilter, (AddressPredicate pred));

    /// Restrict protocols allowed for the initial request.
    MOCK_METHOD(E<void>, allowedProtocols, (std::string_view protocols));

    /// Restrict protocols allowed for redirects.
    MOCK_METHOD(E<void>, allowedRedirectProtocols,
                (std::string_view protocols));
};

} // namespace mw
