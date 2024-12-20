#include <memory>
#include <string>
#include <tuple>
#include <expected>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <mw/error.hpp>
#include <mw/http_server.hpp>

namespace mw
{

HTTPServer::HTTPServer(const std::string& socket_file)
{
    listen = socket_file;
    this->setup();
}

HTTPServer::HTTPServer(const std::string& listen_address, int listen_port)
{
    listen = std::make_tuple(listen_address, listen_port);
    this->setup();
}

E<void> HTTPServer::start()
{
    server_thread = std::thread([&] {
        try
        {
            if(std::holds_alternative<std::string>(listen))
            {
                server.set_address_family(AF_UNIX).listen(
                    std::get<std::string>(listen), 80);
            }
            else
            {
                auto& [addr, port] = std::get<std::tuple<std::string, int>>(listen);
                server.listen(addr, port);}
        }
        catch(const std::exception& e)
        {
            spdlog::error("Failed to listen: {}", e.what());
        }
    });
    while(!server.is_running());
    server.wait_until_ready();
    return {};
}

void HTTPServer::setup()
{
}

void HTTPServer::stop()
{
    should_stop = true;
    server.stop();
}

void HTTPServer::wait()
{
    while(!should_stop && server.is_running());
    server_thread.join();
}

} // namespace mw