#include <array>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <string_view>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
bool writeAll(int fd, const char* data, size_t size)
{
    size_t offset = 0;
    while(offset < size)
    {
        ssize_t count = write(fd, data + offset, size - offset);
        if(count < 0 && errno == EINTR)
        {
            continue;
        }
        if(count <= 0)
        {
            return false;
        }
        offset += count;
    }
    return true;
}
}

int main(int argc, char** argv)
{
    // Every helper has an independent watchdog, including fork descendants.
    alarm(15);
    if(argc < 2)
    {
        return 2;
    }
    std::string_view mode(argv[1]);
    if(mode == "exit")
    {
        return argc > 2 ? std::atoi(argv[2]) : 0;
    }
    if(mode == "signal")
    {
        raise(SIGTERM);
        return 3;
    }
    if(mode == "ignore")
    {
        signal(SIGTERM, SIG_IGN);
        writeAll(1, "ready", 5);
        for(;;)
        {
            pause();
        }
    }
    if(mode == "idle" || mode == "close_stdin")
    {
        if(mode == "close_stdin")
        {
            close(0);
        }
        writeAll(1, "ready", 5);
        for(;;)
        {
            pause();
        }
    }
    if(mode == "capture")
    {
        std::array<char, 65536> buffer;
        buffer.fill('x');
        for(int i = 0; i < 4; ++i)
        {
            if(!writeAll(1, buffer.data(), buffer.size()))
            {
                return 5;
            }
        }
        writeAll(1, "ready", 5);
        for(;;)
        {
            pause();
        }
    }
    if(mode == "descendant")
    {
        pid_t child = fork();
        if(child < 0)
        {
            return 4;
        }
        if(child == 0)
        {
            alarm(5);
            // Retain stdout until the parent's input control channel closes.
            char byte;
            while(read(0, &byte, 1) > 0) {}
            _exit(0);
        }
        writeAll(1, "ready", 5);
        return 0;
    }
    if(mode == "duplex")
    {
        std::array<char, 65536> initial;
        initial.fill('x');
        for(int i = 0; i < 16; ++i)
        {
            if(!writeAll(1, initial.data(), initial.size()))
            {
                return 5;
            }
        }
    }
    if(mode == "gated_drain" && argc > 2)
    {
        int control = std::atoi(argv[2]);
        writeAll(1, "ready", 5);
        char gate;
        ssize_t count;
        do
        {
            count = read(control, &gate, 1);
        } while(count < 0 && errno == EINTR);
        close(control);
        if(count != 1)
        {
            return 7;
        }
        size_t received = 0;
        std::array<char, 8192> buffer;
        for(;;)
        {
            count = read(0, buffer.data(), buffer.size());
            if(count < 0 && errno == EINTR)
            {
                continue;
            }
            if(count < 0)
            {
                return 8;
            }
            if(count == 0)
            {
                std::string reply = std::to_string(received);
                return writeAll(1, reply.data(), reply.size()) ? 0 : 9;
            }
            received += count;
        }
    }
    if(mode == "identity")
    {
        pid_t pid = getpid();
        writeAll(1, reinterpret_cast<const char*>(&pid), sizeof(pid));
        mode = "echo";
    }
    if(mode == "echo" || mode == "duplex")
    {
        std::array<char, 8192> buffer;
        for(;;)
        {
            ssize_t count = read(0, buffer.data(), buffer.size());
            if(count < 0 && errno == EINTR)
            {
                continue;
            }
            if(count == 0)
            {
                return 0;
            }
            if(count < 0 || !writeAll(1, buffer.data(), count))
            {
                return 6;
            }
        }
    }
    return 2;
}
