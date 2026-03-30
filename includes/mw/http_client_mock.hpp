#pragma once

#include <chrono>
#include <string>

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

    MOCK_METHOD(std::chrono::duration<long>, transferTimeout, (), (const, override));
    MOCK_METHOD(E<void>, transferTimeout, (std::chrono::duration<long>), (override));

    MOCK_METHOD(std::chrono::duration<long>, connectionTimeout, (), (const, override));
    MOCK_METHOD(E<void>, connectionTimeout, (std::chrono::duration<long>), (override));

    MOCK_METHOD(long, maxSize, (), (const, override));
    MOCK_METHOD(E<void>, maxSize, (long), (override));

    MOCK_METHOD(long, maxRedirections, (), (const, override));
    MOCK_METHOD(E<void>, maxRedirections, (long), (override));
};

} // namespace mw
