#pragma once

#include <atomic>
#include <string>
#include <tuple>

#include <httplib.h>

#include <mw/error.hpp>
#include <variant>

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

/// @brief A collection of information of a UNIX domain socket file
struct SocketFileInfo
{
    /// The path of the socket file
    std::string filename;
    /// The owner of the socket file. This is either the user name, or
    /// the user ID. If this is -1, the owner is unchanged.
    std::variant<std::string, int> user;
    /// The group of the socket file. This is either the group name,
    /// or the group ID. If this is -1, the group is unchanged.
    std::variant<std::string, int> group;
    /// The integer representation of the permission bits of the
    /// socket file.
    std::optional<unsigned int> permission;

    explicit SocketFileInfo(std::string_view path)
            : filename(path), user(-1), group(-1), permission(std::nullopt)
    {}
};

struct IPSocketInfo
{
    std::string address;
    int port;
};

class HTTPServer
{
public:
    using Request = httplib::Request;
    using Response = httplib::Response;
    using ListenAddress = std::variant<SocketFileInfo, IPSocketInfo>;

    HTTPServer() = delete;

    /// @brief Construct a server that listen to an address or a
    /// socket file.
    explicit HTTPServer(const ListenAddress& listen);
    ~HTTPServer();

    E<void> start();
    void stop();
    void wait();

protected:
    httplib::Server server;

    virtual void setup();

private:
    ListenAddress listen;
    std::atomic<bool> should_stop;
    std::thread server_thread;
};

} // namespace mw
