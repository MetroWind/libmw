#pragma once

#include <chrono>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <gmock/gmock.h>

#include "http_client.hpp"
#include "error.hpp"

namespace mw
{

class HTTPSessionMock : public HTTPSessionInterface
{
public:
    ~HTTPSessionMock() override = default;
    MOCK_METHOD(E<const HTTPResponse*>, get, (const HTTPRequest& req),
                (override));
    MOCK_METHOD(E<const HTTPResponse*>, post, (const HTTPRequest& req),
                (override));

    // Default streaming implementation: replay programmed_chunks via
    // on_chunk and return programmed_response. Tests that need finer
    // control can override these via gmock's ON_CALL/EXPECT_CALL by
    // mocking getStreamImpl/postStreamImpl, but the default behavior
    // covers the common case (e.g. SSE replay).
    E<HTTPResponse> getStream(const HTTPRequest& req,
                              ChunkCallback on_chunk) override
    {
        return runStream(req, std::move(on_chunk));
    }
    E<HTTPResponse> postStream(const HTTPRequest& req,
                               ChunkCallback on_chunk) override
    {
        return runStream(req, std::move(on_chunk));
    }

    // Program the chunks delivered to the streaming callback, and the
    // response (status + headers) returned from the streaming call.
    void setProgrammedChunks(std::vector<std::vector<std::byte>> chunks)
    {
        programmed_chunks = std::move(chunks);
    }
    void setProgrammedResponse(HTTPResponse r)
    {
        programmed_response = std::move(r);
    }

    MOCK_METHOD(std::chrono::duration<long>, transferTimeout, (), (const, override));
    MOCK_METHOD(E<void>, transferTimeout, (std::chrono::duration<long>), (override));

    MOCK_METHOD(std::chrono::duration<long>, connectionTimeout, (), (const, override));
    MOCK_METHOD(E<void>, connectionTimeout, (std::chrono::duration<long>), (override));

    MOCK_METHOD(long, maxSize, (), (const, override));
    MOCK_METHOD(E<void>, maxSize, (long), (override));

    MOCK_METHOD(long, maxRedirections, (), (const, override));
    MOCK_METHOD(E<void>, maxRedirections, (long), (override));

    MOCK_METHOD(bool, followRedirects, (), (const, override));
    MOCK_METHOD(void, followRedirects, (bool), (override));

    MOCK_METHOD(const AddressPredicate&, addressFilter, (), (const, override));
    MOCK_METHOD(void, addressFilter, (AddressPredicate), (override));

    MOCK_METHOD(E<void>, allowedProtocols, (std::string_view), (override));
    MOCK_METHOD(E<void>, allowedRedirectProtocols, (std::string_view),
                (override));

private:
    std::vector<std::vector<std::byte>> programmed_chunks;
    HTTPResponse programmed_response{200, ""};

    E<HTTPResponse> runStream(const HTTPRequest&, ChunkCallback on_chunk)
    {
        for(const auto& chunk: programmed_chunks)
        {
            std::span<const std::byte> view(chunk.data(), chunk.size());
            if(!on_chunk(view))
            {
                return std::unexpected(
                    runtimeError(HTTP_ABORTED_BY_CALLER));
            }
        }
        HTTPResponse out;
        out.status = programmed_response.status;
        out.header = programmed_response.header;
        return out;
    }
};

} // namespace mw
