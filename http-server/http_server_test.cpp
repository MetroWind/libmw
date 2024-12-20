#include <filesystem>

#include <gtest/gtest.h>

#include <mw/http_server.hpp>

namespace mw
{

class Server : public HTTPServer
{
public:
    using HTTPServer::HTTPServer;
protected:
    void setup()
    {
        server.Get("/", [&]([[maybe_unused]] const httplib::Request& req,
                            httplib::Response& res)
        {
            res.status = 200;
            res.set_content("index", "text/plain");
        });
    }
};

TEST(HTTPServer, CanStartServer)
{
    Server server("/tmp/mwtest.socket");
    server.start();

    // TODO: use HTTPSession to get /.

    server.stop();
    server.wait();
    std::filesystem::remove("/tmp/mwtest.socket");
}

} // namespace mw
