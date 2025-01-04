#include <httplib.h>
#include <string>

#include <gtest/gtest.h>

#include <mw/http_server.hpp>
#include <mw/http_client.hpp>
#include <mw/test_utils.hpp>

namespace mw
{

class Server : public HTTPServer
{
public:
    using HTTPServer::HTTPServer;
protected:
    void setup() override
    {
        server.Get("/", [&]([[maybe_unused]] const Request& _, Response& res)
        {
            res.status = 200;
            res.set_content("index", "text/plain");
        });
    }
};

TEST(HTTPServer, CanStartServerOnSocket)
{
    Server server("/tmp/mwtest.socket");
    server.start();
    {
        HTTPSession client("/tmp/mwtest.socket");
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.get("http://localhost/"));
        EXPECT_EQ(res->status, 200);
        EXPECT_EQ(res->payloadAsStr(), "index");
    }
    server.stop();
    server.wait();
}

TEST(HTTPServer, CanStartServer)
{
    Server server("localhost", 8123);
    server.start();
    {
        HTTPSession client;
        ASSIGN_OR_FAIL(const HTTPResponse* res, client.get("http://localhost:8123/"));
        EXPECT_EQ(res->status, 200);
        EXPECT_EQ(res->payloadAsStr(), "index");
    }
    server.stop();
    server.wait();
}

} // namespace mw
