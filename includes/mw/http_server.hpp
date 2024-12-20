#pragma once

#include <atomic>
#include <string>
#include <tuple>

#include <httplib.h>

#include <mw/error.hpp>

#define _ASSIGN_OR_RESPOND_ERROR(tmp, var, val, res)                    \
    auto tmp = val;                                                     \
    if(!tmp.has_value())                                                \
    {                                                                   \
        if(std::holds_alternative<mw::HTTPError>(tmp.error()))          \
        {                                                               \
            const mw::HTTPError& e = std::get<mw::HTTPError>(tmp.error()); \
            res.status = e.code;                                        \
            res.set_content(e.msg, "text/plain");                       \
            return;                                                     \
        }                                                               \
        else                                                            \
        {                                                               \
            res.status = 500;                                           \
            res.set_content(std::visit([](const auto& e) { return e.msg; }, \
                                       tmp.error()),                    \
                            "text/plain");                              \
            return;                                                     \
        }                                                               \
    }                                                                   \
    var = std::move(tmp).value()

// Val should be a rvalue.
#define ASSIGN_OR_RESPOND_ERROR(var, val, res)                          \
    _ASSIGN_OR_RESPOND_ERROR(_CONCAT_NAMES(assign_or_return_tmp, __COUNTER__), \
                            var, val, res)

namespace mw
{

class HTTPServer
{
public:
    HTTPServer() = delete;
    explicit HTTPServer(const std::string& socket_file);
    HTTPServer(const std::string& listen_address, int listen_port);

    E<void> start();
    void stop();
    void wait();

protected:
    httplib::Server server;

    void setup();

private:
    std::variant<std::string, std::tuple<std::string, int>> listen;
    std::atomic<bool> should_stop;
    std::thread server_thread;
};

} // namespace mw
