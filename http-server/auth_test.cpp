#include <memory>
#include <chrono>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <spdlog/spdlog.h>
#include <mw/error.hpp>
#include <mw/http_client.hpp>
#include <mw/http_client_mock.hpp>
#include <mw/auth.hpp>

using ::testing::Return;

class DebugLogEnv : public ::testing::Environment
{
public:
    ~DebugLogEnv() override = default;
    void SetUp() override
    {
        spdlog::set_level(spdlog::level::debug);
    }
};

testing::Environment* const debug_log_env =
    testing::AddGlobalTestEnvironment(new DebugLogEnv);

TEST(Auth, CanInitiate)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_code(200, "Some login page");
    EXPECT_CALL(*http, get(
        mw::HTTPRequest("https://example.com/auth?response_type=code"
                        "&client_id=client%20id"
                        "&redirect_uri=http%3A%2F%2Flocalhost%2F"
                        "&scope=openid%20profile")))
        .WillOnce(Return(&res_code));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "", "http://localhost/",
        std::move(http));

    mw::E<mw::HTTPResponse> res = (*auth)->initiate();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->payloadAsStr(), "Some login page");
    EXPECT_EQ(res->status, 200);
}

TEST(Auth, CreateCanHandleServerConfError)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(500, "");
    EXPECT_CALL(
        *http, get(mw::HTTPRequest("https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "", "http://localhost/",
        std::move(http));
    ASSERT_FALSE(auth.has_value());
    EXPECT_EQ(std::visit([&](auto e) { return e.msg; }, auth.error()),
              "Invalid OpenID configuration from server");
}

TEST(Auth, CreateCanHandleInvalidJSON)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, "invalid json");
    EXPECT_CALL(
        *http, get(mw::HTTPRequest("https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "", "http://localhost/",
        std::move(http));
    ASSERT_FALSE(auth.has_value());
    EXPECT_EQ(std::visit([&](auto e) { return e.msg; }, auth.error()),
              "Invalid OpenID configuration from server");
}

TEST(Auth, CreateCanHandleFaultyServer)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    EXPECT_CALL(
        *http, get(mw::HTTPRequest("https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(std::unexpected(mw::runtimeError("server died"))));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "", "http://localhost/",
        std::move(http));
    ASSERT_FALSE(auth.has_value());
    EXPECT_EQ(std::visit([&](auto e) { return e.msg; }, auth.error()),
              "server died");
}

TEST(Auth, InitiateJustPropagateServerError)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
                               "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_code(500, "");
    EXPECT_CALL(*http, get(
        mw::HTTPRequest(
            "https://example.com/auth?response_type=code"
            "&client_id=client%20id"
            "&redirect_uri=http%3A%2F%2Flocalhost%2F"
            "&scope=openid%20profile")))
        .WillOnce(Return(&res_code));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "", "http://localhost/",
        std::move(http));

    mw::E<mw::HTTPResponse> res = (*auth)->initiate();
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res->payload.empty());
    EXPECT_EQ(res->status, 500);
}

TEST(Auth, CanGetTokens)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_token(200, R"(
 {
   "access_token": "aaa",
   "token_type": "Bearer",
   "expires_in": 3600,
   "refresh_token": "bbb",
   "id_token": "ccc"
  }
)");

    EXPECT_CALL(*http, post(
                    mw::HTTPRequest("https://example.com/token")
                    .setPayload("grant_type=authorization_code&code=some%20code"
                                "&redirect_uri=http%3A%2F%2Flocalhost%2F"
                                "&client_id=client%20id"
                                "&client_secret=client%20secret")
                    .addHeader("Content-Type", "application/x-www-form-urlencoded")
                    .addHeader("Authorization", "Basic client%20secret")))
        .WillOnce(Return(&res_token));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com/", "client id", "client secret",
        "http://localhost/", std::move(http));

    mw::E<mw::Tokens> tokens = (*auth)->authenticate("some code");
    ASSERT_TRUE(tokens.has_value());
    EXPECT_EQ(tokens->access_token, "aaa");
    EXPECT_EQ(tokens->refresh_token, "bbb");
    using namespace std::literals;
    EXPECT_LT(std::chrono::abs(*(tokens->expiration) - (mw::Clock::now() + 1h)), 1s);
}

TEST(Auth, AuthenticateCanHandleFailedQuery)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_token(500, "");
    EXPECT_CALL(*http, post(mw::HTTPRequest("https://example.com/token")
                            .setPayload("grant_type=authorization_code&code=some%20code"
                                        "&redirect_uri=http%3A%2F%2Flocalhost%2F"
                                        "&client_id=client%20id"
                                        "&client_secret=client%20secret")
                            .addHeader("Content-Type", "application/x-www-form-urlencoded")
                            .addHeader("Authorization", "Basic client%20secret")))
        .WillOnce(Return(&res_token));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com", "client id", "client secret",
        "http://localhost/", std::move(http));

    mw::E<mw::Tokens> tokens = (*auth)->authenticate("some code");
    ASSERT_FALSE(tokens.has_value());
    mw::Error expected = mw::HTTPError{500, ""};
    EXPECT_EQ(tokens.error(), expected);
}

TEST(Auth, AuthenticateCanHandleServerFault)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    EXPECT_CALL(*http, post(
        mw::HTTPRequest("https://example.com/token")
        .setPayload("grant_type=authorization_code&code=some%20code"
                    "&redirect_uri=http%3A%2F%2Flocalhost%2F"
                    "&client_id=client%20id"
                    "&client_secret=client%20secret")
        .addHeader("Content-Type", "application/x-www-form-urlencoded")
        .addHeader("Authorization", "Basic client%20secret")))
        .WillOnce(Return(std::unexpected(mw::runtimeError("error"))));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com", "client id", "client secret",
        "http://localhost/", std::move(http));
    mw::E<mw::Tokens> tokens = (*auth)->authenticate("some code");
    ASSERT_FALSE(tokens.has_value());
    EXPECT_EQ(tokens.error(), mw::Error(mw::RuntimeError{"error"}));
}

TEST(Auth, AuthenticateCanHandleInvalidJSON)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_token(200, "invalid json");
    EXPECT_CALL(*http, post(
        mw::HTTPRequest("https://example.com/token")
        .setPayload("grant_type=authorization_code&code=some%20code"
                    "&redirect_uri=http%3A%2F%2Flocalhost%2F"
                    "&client_id=client%20id"
                    "&client_secret=client%20secret")
        .addHeader("Content-Type", "application/x-www-form-urlencoded")
        .addHeader("Authorization", "Basic client%20secret")))
        .WillOnce(Return(&res_token));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com", "client id", "client secret",
        "http://localhost/", std::move(http));
    mw::E<mw::Tokens> tokens = (*auth)->authenticate("some code");
    ASSERT_FALSE(tokens.has_value());
    EXPECT_EQ(tokens.error(), mw::runtimeError("Invalid token response"));
}

TEST(Auth, CanRefreshTokens)
{
    auto http = std::make_unique<mw::HTTPSessionMock>();
    mw::HTTPResponse res_conf(200, R"(
{
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "introspection_endpoint": "https://example.com/token/introspect",
    "userinfo_endpoint": "https://example.com/userinfo",
    "end_session_endpoint": "https://example.com/logout"
}
)");

    EXPECT_CALL(*http, get(mw::HTTPRequest(
        "https://example.com/.well-known/openid-configuration")))
        .WillOnce(Return(&res_conf));

    mw::HTTPResponse res_token(200, R"(
 {
   "access_token": "aaa",
   "token_type": "Bearer",
   "expires_in": 3600,
   "refresh_token": "bbb"
 }
)");

    EXPECT_CALL(*http, post(
        mw::HTTPRequest("https://example.com/token")
        .setPayload("client_id=client%20id"
                    "&client_secret=client%20secret"
                    "&grant_type=refresh_token"
                    "&refresh_token=lalala"
                    "&scope=openid%20profile")
        .addHeader("Content-Type", "application/x-www-form-urlencoded")
        .addHeader("Authorization", "Basic client%20secret")))
        .WillOnce(Return(&res_token));

    auto auth = mw::AuthOpenIDConnect::create(
        "https://example.com", "client id", "client secret",
        "http://localhost/", std::move(http));
    mw::E<mw::Tokens> tokens = (*auth)->refreshTokens("lalala");
    ASSERT_TRUE(tokens.has_value());
    EXPECT_EQ(tokens->access_token, "aaa");
    EXPECT_EQ(tokens->refresh_token, "bbb");
    using namespace std::literals;
    EXPECT_LT(std::chrono::abs(*(tokens->expiration) - (mw::Clock::now() + 1h)), 1s);
}
