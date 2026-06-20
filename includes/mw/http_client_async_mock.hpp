#pragma once

#include <chrono>
#include <string_view>
#include <utility>

#include <gmock/gmock.h>

#include "http_client_async.hpp"

namespace mw
{

/// Google Mock test double for HTTPSessionAsync.
class HTTPSessionAsyncMock : public HTTPSessionAsyncInterface
{
public:
    /// Destroy the mock session.
    ~HTTPSessionAsyncMock() override = default;

    /// Create a task that immediately completes with result.
    static Task<E<HTTPResponse>> complete(E<HTTPResponse> result)
    {
        co_return std::move(result);
    }

    /// Start an HTTP GET request and complete with a buffered response.
    MOCK_METHOD((Task<E<HTTPResponse>>), get, (HTTPRequest req), (override));

    /// Start an HTTP POST request and complete with a buffered response.
    MOCK_METHOD((Task<E<HTTPResponse>>), post, (HTTPRequest req), (override));

    /// Start an HTTP GET request and deliver chunks on the driver thread.
    MOCK_METHOD((Task<E<HTTPResponse>>), getStream,
                (HTTPRequest req, ChunkCallback on_chunk), (override));

    /// Start an HTTP POST request and deliver chunks on the driver thread.
    MOCK_METHOD((Task<E<HTTPResponse>>), postStream,
                (HTTPRequest req, ChunkCallback on_chunk), (override));

    /// Return the timeout for the full transfer. Zero means no timeout.
    MOCK_METHOD(std::chrono::duration<long>, transferTimeout, (),
                (const, override));

    /// Set the timeout for the full transfer. Zero means no timeout.
    MOCK_METHOD(E<void>, transferTimeout, (std::chrono::duration<long>),
                (override));

    /// Return the connection timeout.
    MOCK_METHOD(std::chrono::duration<long>, connectionTimeout, (),
                (const, override));

    /// Set the connection timeout.
    MOCK_METHOD(E<void>, connectionTimeout, (std::chrono::duration<long>),
                (override));

    /// Return the maximum accepted download size.
    MOCK_METHOD(long, maxSize, (), (const, override));

    /// Set the maximum accepted download size.
    MOCK_METHOD(E<void>, maxSize, (long), (override));

    /// Return the redirect cap.
    MOCK_METHOD(long, maxRedirections, (), (const, override));

    /// Set the redirect cap.
    MOCK_METHOD(E<void>, maxRedirections, (long), (override));

    /// Return whether redirects are followed.
    MOCK_METHOD(bool, followRedirects, (), (const, override));

    /// Set whether redirects are followed.
    MOCK_METHOD(void, followRedirects, (bool), (override));

    /// Return the connect-time address filter.
    MOCK_METHOD(const AddressPredicate&, addressFilter, (),
                (const, override));

    /// Set the connect-time address filter.
    MOCK_METHOD(void, addressFilter, (AddressPredicate pred), (override));

    /// Restrict protocols allowed for the initial request.
    MOCK_METHOD(E<void>, allowedProtocols, (std::string_view protocols),
                (override));

    /// Restrict protocols allowed for redirects.
    MOCK_METHOD(E<void>, allowedRedirectProtocols,
                (std::string_view protocols), (override));
};

} // namespace mw
