#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#include <exception>
#include <filesystem>
#include <string>
#include <thread>
#include <variant>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <mw/error.hpp>
#include <mw/http_server.hpp>

namespace mw
{

HTTPServer::HTTPServer(const ListenAddress& listen_)
        : listen(listen_) {}

HTTPServer::~HTTPServer()
{
    if(std::holds_alternative<SocketFileInfo>(listen))
    {
        const SocketFileInfo& sock = std::get<SocketFileInfo>(listen);
        if(std::filesystem::exists(sock.filename))
        {
            std::filesystem::remove(sock.filename);
        }
    }
}

E<void> HTTPServer::start()
{
    this->setup();
    server_thread = std::thread([&] {
        try
        {
            if(std::holds_alternative<SocketFileInfo>(listen))
            {
                server.set_address_family(AF_UNIX).listen(
                    std::get<SocketFileInfo>(listen).filename, 80);
            }
            else
            {
                const IPSocketInfo sock = std::get<IPSocketInfo>(listen);
                server.listen(sock.address, sock.port);
            }
        }
        catch(const std::exception& e)
        {
            spdlog::error("Failed to listen: {}", e.what());
        }
    });
    while(!server.is_running());
    server.wait_until_ready();
    if(std::holds_alternative<SocketFileInfo>(listen))
    {
        const SocketFileInfo& sock = std::get<SocketFileInfo>(listen);
        if(sock.permission.has_value())
        {
            if(chmod(sock.filename.c_str(), *sock.permission) != 0)
            {
                spdlog::error(
                    "Failed to change permmision on the socket file: {}",
                    strerror(errno));
            }
        }

        uid_t uid = 0;
        if(std::holds_alternative<std::string>(sock.user))
        {
            const std::string& user = std::get<std::string>(sock.user);
            passwd* pw = getpwnam(user.c_str());
            if(pw == nullptr)
            {
                spdlog::error("Failed to set owner on the socket file. "
                              "User not found: {}", user.c_str());
            }
            uid = pw->pw_uid;
        }
        else
        {
            uid = std::get<int>(sock.user);
        }

        gid_t gid = 0;
        if(std::holds_alternative<std::string>(sock.group))
        {
            const std::string& the_group = std::get<std::string>(sock.group);
            group* g = getgrnam(the_group.c_str());
            if(g == nullptr)
            {
                spdlog::error("Failed to set group on the socket file. "
                              "Group not found: {}", the_group.c_str());
            }
            gid = g->gr_gid;
        }
        else
        {
            gid = std::get<int>(sock.group);
        }

        if(chown(sock.filename.c_str(), uid, gid) != 0)
        {
            spdlog::error("Failed to set owner and group on the socket file: {}",
                          strerror(errno));
        }
    }
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
    server_thread.join();
    if(std::holds_alternative<SocketFileInfo>(listen))
    {
        std::filesystem::remove(std::get<SocketFileInfo>(listen).filename);
    }
}

} // namespace mw
