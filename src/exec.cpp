#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "exec.hpp"
#ifdef LIBMW_PROCESS_TESTING
#include "process_test_hooks.hpp"
#endif

#include <algorithm>
#include <cerrno>
#include <climits>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>

#if !defined(__linux__) || !defined(__GLIBC__) || !__GLIBC_PREREQ(2, 24)
#error "Process requires Linux with glibc 2.24 or newer"
#endif

extern char** environ;

namespace mw
{
#ifdef LIBMW_PROCESS_TESTING
thread_local process_test::Faults process_test::faults;
#endif
namespace
{
using Clock = std::chrono::steady_clock;
using Deadline = std::optional<ProcessDeadline>;
constexpr size_t IO_CHUNK = 65536;

ssize_t readPipe(int fd, char* data, size_t size)
{
#ifdef LIBMW_PROCESS_TESTING
    if(process_test::faults.read_interruptions > 0)
    {
        --process_test::faults.read_interruptions;
        errno = EINTR;
        return -1;
    }
#endif
    return ::read(fd, data, size);
}

ssize_t writePipe(int fd, const char* data, size_t size)
{
#ifdef LIBMW_PROCESS_TESTING
    auto& faults = process_test::faults;
    if(faults.zero_write)
    {
        return 0;
    }
    if(faults.write_interruptions > 0)
    {
        --faults.write_interruptions;
        errno = EINTR;
        return -1;
    }
    if(faults.write_calls_before_error == 0)
    {
        errno = EPIPE;
        return -1;
    }
    if(faults.write_calls_before_error > 0)
    {
        --faults.write_calls_before_error;
        size = std::min(size, size_t(4));
    }
#endif
    return ::write(fd, data, size);
}

pid_t queryChild(pid_t pid, int* status)
{
#ifdef LIBMW_PROCESS_TESTING
    if(process_test::faults.wait_interruptions > 0)
    {
        --process_test::faults.wait_interruptions;
        errno = EINTR;
        return -1;
    }
#endif
    return waitpid(pid, status, WNOHANG);
}

ProcessError processError(std::string_view operation, int code,
                          size_t progress = 0)
{
    std::string msg(operation);
    if(code)
    {
        msg += ": ";
        msg += strerror(code);
    }
    return {std::move(msg), code, progress};
}

void closeRaw(int& fd) noexcept
{
    int old_fd = std::exchange(fd, -1);
    if(old_fd >= 0)
    {
        ::close(old_fd);
    }
}

E<void> closeEndpoint(int& fd)
{
    int old_fd = std::exchange(fd, -1);
    if(old_fd >= 0 && ::close(old_fd) < 0)
    {
        return std::unexpected(processError("close pipe", errno));
    }
    return {};
}

E<void> nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if(flags < 0)
    {
        return std::unexpected(processError("get pipe flags", errno));
    }
    if(!(flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        return std::unexpected(processError("set nonblocking pipe", errno));
    }
    return {};
}

bool expired(Deadline deadline)
{
    return deadline && Clock::now() >= *deadline;
}

int pollTimeout(Deadline deadline)
{
    if(!deadline)
    {
        return -1;
    }
    auto remaining = *deadline - Clock::now();
    if(remaining <= Clock::duration::zero())
    {
        return 0;
    }
    auto ms = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
    return static_cast<int>(std::min(ms, static_cast<decltype(ms)>(INT_MAX)));
}

E<bool> ready(int fd, short events, Deadline deadline)
{
    while(!expired(deadline))
    {
        pollfd descriptor{fd, events, 0};
#ifdef LIBMW_PROCESS_TESTING
        ++process_test::faults.poll_calls;
#endif
        int result = poll(&descriptor, 1, pollTimeout(deadline));
        if(result > 0)
        {
            if(descriptor.revents & POLLNVAL)
            {
                return std::unexpected(processError("poll pipe", EBADF));
            }
            return true;
        }
        if(result < 0 && errno != EINTR)
        {
            return std::unexpected(processError("poll pipe", errno));
        }
    }
    return false;
}

E<PipeReadResult> readEngine(int fd, size_t max_bytes, Deadline deadline,
                            bool immediate)
{
    if(fd < 0 || max_bytes == 0)
    {
        return std::unexpected(processError("Invalid pipe read", 0));
    }
    std::string buffer(std::min(max_bytes, static_cast<size_t>(SSIZE_MAX)),
                       '\0');
    for(;;)
    {
        ssize_t count = readPipe(fd, buffer.data(), buffer.size());
        if(count > 0)
        {
            buffer.resize(count);
            return PipeReadResult{PipeState::COMPLETE, std::move(buffer)};
        }
        if(count == 0)
        {
            return PipeReadResult{PipeState::EOF_REACHED, {}};
        }
        int code = errno;
        if(code == EINTR)
        {
            if(expired(deadline))
            {
                return PipeReadResult{PipeState::DEADLINE_EXPIRED, {}};
            }
            continue;
        }
        if(code != EAGAIN && code != EWOULDBLOCK)
        {
            return std::unexpected(processError("read pipe", code));
        }
        if(immediate)
        {
            return PipeReadResult{PipeState::WOULD_BLOCK, {}};
        }
        auto wait = ready(fd, POLLIN, deadline);
        if(!wait)
        {
            return std::unexpected(wait.error());
        }
        if(!*wait)
        {
            return PipeReadResult{PipeState::DEADLINE_EXPIRED, {}};
        }
    }
}

// No process-wide disposition changes. Cleanup never allocates.
struct SigpipeGuard
{
    sigset_t saved{};
    sigset_t blocked{};
    bool active = false;
    bool pending_before = false;
    bool broken = false;

    int establish() noexcept
    {
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGPIPE);
        int code = pthread_sigmask(SIG_BLOCK, &blocked, &saved);
        if(code)
        {
            return code;
        }
        active = true;
        sigset_t pending;
        if(sigpending(&pending) < 0)
        {
            return errno;
        }
        pending_before = sigismember(&pending, SIGPIPE) == 1;
        return 0;
    }

    int restore() noexcept
    {
        if(!active)
        {
            return 0;
        }
        int cleanup_error = 0;
        if(broken && !pending_before)
        {
            timespec zero{};
            int result;
            do
            {
                result = sigtimedwait(&blocked, nullptr, &zero);
            } while(result < 0 && errno == EINTR);
            if(result < 0 && errno != EAGAIN)
            {
                cleanup_error = errno;
            }
        }
        int code = pthread_sigmask(SIG_SETMASK, &saved, nullptr);
        active = false;
        return cleanup_error ? cleanup_error : code;
    }

    ~SigpipeGuard() noexcept { restore(); }
};

E<PipeWriteResult> writeEngine(int fd, std::string_view data,
                              Deadline deadline)
{
    if(fd < 0)
    {
        return std::unexpected(processError("Invalid pipe write", 0));
    }
    if(data.empty())
    {
        return PipeWriteResult{PipeState::COMPLETE, 0};
    }
    SigpipeGuard guard;
    int code = guard.establish();
    if(code)
    {
        return std::unexpected(processError("block SIGPIPE", code));
    }
    size_t offset = 0;
    PipeState state = PipeState::COMPLETE;
    std::optional<ProcessError> failure;
    while(offset < data.size())
    {
        ssize_t count = writePipe(fd, data.data() + offset,
                               std::min(IO_CHUNK, data.size() - offset));
        if(count > 0)
        {
            offset += count;
        }
        else if(count == 0)
        {
            failure = processError("zero-progress pipe write", EIO, offset);
            break;
        }
        else
        {
            code = errno;
            if(code != EINTR && code != EAGAIN && code != EWOULDBLOCK)
            {
                guard.broken = code == EPIPE;
                failure = processError("write pipe", code, offset);
                break;
            }
            if(code != EINTR)
            {
                auto wait = ready(fd, POLLOUT, deadline);
                if(!wait)
                {
                    failure = *wait.error().as<ProcessError>();
                    failure->bytes_transferred = offset;
                    break;
                }
                if(!*wait)
                {
                    state = PipeState::DEADLINE_EXPIRED;
                    break;
                }
            }
        }
        if(offset < data.size() && expired(deadline))
        {
            state = PipeState::DEADLINE_EXPIRED;
            break;
        }
    }
    code = guard.restore();
    if(failure)
    {
        if(code)
        {
            failure->msg += "; SIGPIPE cleanup failed: ";
            failure->msg += strerror(code);
        }
        return std::unexpected(std::move(*failure));
    }
    if(code)
    {
        return std::unexpected(processError("restore SIGPIPE mask", code,
                                             offset));
    }
    return PipeWriteResult{state, offset};
}

ProcessDeadline after(std::chrono::milliseconds duration)
{
    auto now = Clock::now();
    auto capacity = std::chrono::duration_cast<std::chrono::milliseconds>(
        ProcessDeadline::max() - now);
    if(duration >= capacity)
    {
        return ProcessDeadline::max();
    }
    return now + duration;
}

struct Descriptor
{
    int fd = -1;
    ~Descriptor() noexcept { closeRaw(fd); }
};

E<void> prepareSource(int fd, Descriptor& source)
{
    if(fd < 0)
    {
        return std::unexpected(processError("Closed child stream", 0));
    }
    int flags = fcntl(fd, F_GETFL);
    if(flags < 0)
    {
        return std::unexpected(processError("get child flags", errno));
    }
    if(flags & O_NONBLOCK)
    {
        return std::unexpected(processError(
            "Nonblocking child stream; use a fresh pipe", 0));
    }
    source.fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if(source.fd < 0)
    {
        return std::unexpected(processError("copy child stream", errno));
    }
    return {};
}

struct SpawnActions
{
    posix_spawn_file_actions_t actions;
    bool initialized = false;
    ~SpawnActions() noexcept
    {
        if(initialized)
        {
            posix_spawn_file_actions_destroy(&actions);
        }
    }
};
} // namespace

Pipe::Pipe(Pipe&& rhs) noexcept : fds(std::exchange(rhs.fds, {-1, -1})) {}

Pipe& Pipe::operator=(Pipe&& rhs) noexcept
{
    if(this != &rhs)
    {
        closeRaw(fds[0]);
        closeRaw(fds[1]);
        fds = std::exchange(rhs.fds, {-1, -1});
    }
    return *this;
}

Pipe::~Pipe() noexcept
{
    closeRaw(fds[0]);
    closeRaw(fds[1]);
}

E<Pipe> Pipe::create()
{
    Pipe result;
    if(pipe2(result.fds.data(), O_CLOEXEC) < 0)
    {
        return std::unexpected(processError("create pipe", errno));
    }
    return result;
}

E<void> Pipe::closeInput() { return closeEndpoint(fds[1]); }
E<void> Pipe::closeOutput() { return closeEndpoint(fds[0]); }

E<int> Pipe::dupInput(int fd) const
{
    int result = dup2(inputFD(), fd);
    if(result < 0)
    {
        return std::unexpected(processError("duplicate pipe input", errno));
    }
    return result;
}

E<int> Pipe::dupOutput(int fd) const
{
    int result = dup2(outputFD(), fd);
    if(result < 0)
    {
        return std::unexpected(processError("duplicate pipe output", errno));
    }
    return result;
}

E<void> Pipe::prepare(size_t endpoint) const
{
    if(fds[endpoint] < 0)
    {
        return std::unexpected(processError("Closed pipe endpoint", 0));
    }
    std::lock_guard lock(setup_mutex[endpoint]);
    return nonblocking(fds[endpoint]);
}

E<PipeReadResult> Pipe::tryRead(size_t max_bytes) const
{
    if(max_bytes == 0)
    {
        return std::unexpected(processError("Zero pipe read size", 0));
    }
    auto setup = prepare(0);
    if(!setup)
    {
        return std::unexpected(setup.error());
    }
    return readEngine(outputFD(), max_bytes, {}, true);
}

E<PipeReadResult> Pipe::readChunk(size_t max_bytes,
                                ProcessDeadline deadline) const
{
    if(max_bytes == 0)
    {
        return std::unexpected(processError("Zero pipe read size", 0));
    }
    auto setup = prepare(0);
    if(!setup)
    {
        return std::unexpected(setup.error());
    }
    return readEngine(outputFD(), max_bytes, deadline, false);
}

E<PipeWriteResult> Pipe::writeUntil(std::string_view data,
                                  ProcessDeadline deadline) const
{
    auto setup = prepare(1);
    if(!setup)
    {
        return std::unexpected(setup.error());
    }
    return writeEngine(inputFD(), data, deadline);
}

E<std::string> Pipe::read() const
{
    auto setup = prepare(0);
    if(!setup)
    {
        return std::unexpected(setup.error());
    }
    std::string result;
    for(;;)
    {
        auto chunk = readEngine(outputFD(), IO_CHUNK, {}, false);
        if(!chunk)
        {
            return std::unexpected(chunk.error());
        }
        if(chunk->state == PipeState::EOF_REACHED)
        {
            return result;
        }
        result += chunk->data;
    }
}

E<void> Pipe::write(std::string_view data) const
{
    auto setup = prepare(1);
    if(!setup)
    {
        return std::unexpected(setup.error());
    }
    auto result = writeEngine(inputFD(), data, {});
    if(!result)
    {
        return std::unexpected(result.error());
    }
    return {};
}

struct Process::Impl
{
    pid_t pid = 0;
    std::optional<ProcessExit> exit;
    std::optional<ProcessError> ownership_error;
    Pipe input_pipe;
    Pipe output_pipe;
    int wake = -1;
    std::string input;
    size_t offset = 0;
    std::string* output = nullptr;
    std::thread pump;
    std::mutex mutex;
    std::condition_variable changed;
    bool started = false;
    bool cancel = false;
    bool stop_input = false;
    bool done = true;
    bool output_complete = true;
    bool fallback_error = false;
    std::optional<ProcessError> io_error;
    std::list<std::string> chunks;
    std::list<std::string> publishing;

    void command(bool cancel_all) noexcept
    {
        {
            std::lock_guard lock(mutex);
            cancel |= cancel_all;
            stop_input = true;
            changed.notify_all();
        }
        if(wake >= 0)
        {
            uint64_t value = 1;
            ssize_t count;
            do
            {
                count = ::write(wake, &value, sizeof(value));
            } while(count < 0 && errno == EINTR);
        }
    }

    ~Impl() noexcept
    {
        command(true);
        if(pid > 0)
        {
            // Observe before signaling; ECHILD invalidates ownership.
            int raw_status;
            pid_t result;
            do
            {
                result = waitpid(pid, &raw_status, WNOHANG);
            } while(result < 0 && errno == EINTR);
            if(result == pid || (result < 0 && errno == ECHILD))
            {
                pid = 0;
            }
            if(pid > 0)
            {
                ::kill(pid, SIGKILL);
                do
                {
                    result = waitpid(pid, &raw_status, 0);
                } while(result < 0 && errno == EINTR);
                pid = 0;
            }
        }
        if(pump.joinable())
        {
            pump.join();
        }
        closeRaw(wake);
    }

    void run() noexcept
    {
        try
        {
            {
                std::unique_lock lock(mutex);
                changed.wait(lock, [this] { return started || cancel; });
                if(cancel)
                {
                    done = true;
                    changed.notify_all();
                    return;
                }
            }
            pumpIO();
        }
        catch(...)
        {
            std::lock_guard lock(mutex);
            fallback_error = true;
        }
        // Raw cleanup avoids allocations in thread failure handling.
        input_pipe = Pipe{};
        output_pipe = Pipe{};
        std::lock_guard lock(mutex);
        done = true;
        changed.notify_all();
    }

    void pumpIO()
    {
        for(;;)
        {
            bool stop;
            {
                std::lock_guard lock(mutex);
                if(cancel)
                {
                    return;
                }
                stop = stop_input;
            }
            if(stop || offset == input.size())
            {
                auto closed = input_pipe.closeInput();
                if(!closed)
                {
                    fail(closed.error());
                    return;
                }
            }
            if(input_pipe.inputFD() < 0 && output_pipe.outputFD() < 0)
            {
                return;
            }
            pollfd descriptors[] = {
                {wake, POLLIN, 0},
                {input_pipe.inputFD(), POLLOUT, 0},
                {output_pipe.outputFD(), POLLIN, 0},
            };
            int result = poll(descriptors, 3, -1);
            if(result < 0)
            {
                if(errno == EINTR)
                {
                    continue;
                }
                fail(Error(processError("poll managed I/O", errno)));
                return;
            }
            if(descriptors[0].revents)
            {
                uint64_t value;
                while(::read(wake, &value, sizeof(value)) < 0 && errno == EINTR)
                {}
                continue;
            }
            if(descriptors[1].revents)
            {
                auto written = writeEngine(input_pipe.inputFD(),
                    std::string_view(input).substr(offset, IO_CHUNK),
                    Clock::now());
                if(!written)
                {
                    fail(written.error());
                    return;
                }
                offset += written->bytes_written;
            }
            if(descriptors[2].revents)
            {
                auto chunk = readEngine(output_pipe.outputFD(), IO_CHUNK,
                                         {}, true);
                if(!chunk)
                {
                    fail(chunk.error());
                    return;
                }
                if(chunk->state == PipeState::EOF_REACHED)
                {
                    auto closed = output_pipe.closeOutput();
                    std::lock_guard lock(mutex);
                    output_complete = true;
                    if(!closed)
                    {
                        io_error = *closed.error().as<ProcessError>();
                        return;
                    }
                }
                else if(chunk->state == PipeState::COMPLETE)
                {
                    // Allocate the node before acquiring the mutex.
                    std::list<std::string> incoming;
                    incoming.push_back(std::move(chunk->data));
                    std::lock_guard lock(mutex);
                    chunks.splice(chunks.end(), incoming);
                }
            }
        }
    }

    void fail(const Error& error)
    {
        std::lock_guard lock(mutex);
        io_error = *error.as<ProcessError>();
    }

    E<void> publish()
    {
        if(!output)
        {
            return {};
        }
        {
            std::lock_guard lock(mutex);
            publishing.splice(publishing.end(), chunks);
        }
        try
        {
            while(!publishing.empty())
            {
                output->append(publishing.front());
                publishing.pop_front();
            }
        }
        catch(const std::exception& error)
        {
            return std::unexpected(processError(error.what(), 0));
        }
        return {};
    }
};

Process::Process() noexcept = default;
Process::Process(Process&& rhs) noexcept = default;
Process& Process::operator=(Process&& rhs) noexcept
{
    if(this != &rhs)
    {
        impl = std::move(rhs.impl);
    }
    return *this;
}
Process::~Process() noexcept = default;

E<Process> Process::execArgs(Input input,
                            std::span<const std::string_view> args,
                            Output output)
{
    try
    {
        if(args.empty() || args.front().empty())
        {
            return std::unexpected(processError("Empty process command", 0));
        }
        std::vector<std::string> owned_args;
        for(auto arg: args)
        {
            if(arg.find('\0') != std::string_view::npos)
            {
                return std::unexpected(processError("NUL in argv", 0));
            }
            owned_args.emplace_back(arg);
        }
        std::vector<char*> argv;
        for(auto& arg: owned_args)
        {
            argv.push_back(arg.data());
        }
        argv.push_back(nullptr);
        Process process;
        process.impl = std::make_unique<Impl>();
        auto& state = *process.impl;
        Pipe* child_input = nullptr;
        Pipe* child_output = nullptr;
        if(auto pipe = std::get_if<Pipe*>(&input))
        {
            if(!*pipe)
            {
                return std::unexpected(processError("Null stdin pipe", 0));
            }
            child_input = *pipe;
        }
        else if(auto text = std::get_if<std::string_view>(&input))
        {
            state.input.assign(*text);
            auto pipe = Pipe::create();
            if(!pipe)
            {
                return std::unexpected(pipe.error());
            }
            state.input_pipe = std::move(*pipe);
            child_input = &state.input_pipe;
            auto setup = nonblocking(child_input->inputFD());
            if(!setup)
            {
                return std::unexpected(setup.error());
            }
        }
        if(auto pipe = std::get_if<Pipe*>(&output))
        {
            if(!*pipe)
            {
                return std::unexpected(processError("Null stdout pipe", 0));
            }
            child_output = *pipe;
        }
        else if(auto text = std::get_if<std::string*>(&output))
        {
            if(!*text)
            {
                return std::unexpected(processError("Null capture string", 0));
            }
            state.output = *text;
            state.output_complete = false;
            auto pipe = Pipe::create();
            if(!pipe)
            {
                return std::unexpected(pipe.error());
            }
            state.output_pipe = std::move(*pipe);
            child_output = &state.output_pipe;
            auto setup = nonblocking(child_output->outputFD());
            if(!setup)
            {
                return std::unexpected(setup.error());
            }
        }
        if(child_input && child_input == child_output)
        {
            return std::unexpected(processError(
                "Incompatible pipe routing", 0));
        }
        Descriptor input_source;
        Descriptor output_source;
        if(child_input)
        {
            auto prepared = prepareSource(
                child_input->outputFD(), input_source);
            if(!prepared)
            {
                return std::unexpected(prepared.error());
            }
        }
        if(child_output)
        {
            auto prepared = prepareSource(
                child_output->inputFD(), output_source);
            if(!prepared)
            {
                return std::unexpected(prepared.error());
            }
        }
        SpawnActions actions;
        int code = posix_spawn_file_actions_init(&actions.actions);
        if(code)
        {
            return std::unexpected(processError(
                "initialize spawn actions", code));
        }
        actions.initialized = true;
        for(auto [source, target]: {std::pair{input_source.fd, STDIN_FILENO},
                                    std::pair{output_source.fd, STDOUT_FILENO}})
        {
            if(source >= 0)
            {
                code = posix_spawn_file_actions_adddup2(&actions.actions,
                                                        source, target);
                if(code)
                {
                    return std::unexpected(processError("spawn dup2", code));
                }
            }
        }
        std::vector<int> close_fds;
        for(Pipe* pipe: {child_input, child_output})
        {
            if(pipe)
            {
                close_fds.push_back(pipe->inputFD());
                close_fds.push_back(pipe->outputFD());
            }
        }
        close_fds.push_back(input_source.fd);
        close_fds.push_back(output_source.fd);
        for(int fd: close_fds)
        {
            if(fd < 0 || (fd == STDIN_FILENO && child_input) ||
               (fd == STDOUT_FILENO && child_output))
            {
                continue;
            }
            code = posix_spawn_file_actions_addclose(&actions.actions, fd);
            if(code)
            {
                return std::unexpected(processError("spawn close", code));
            }
        }
        if(state.output || std::holds_alternative<std::string_view>(input))
        {
            state.wake = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if(state.wake < 0)
            {
                return std::unexpected(processError("create pump wake", errno));
            }
            state.done = false;
            state.pump = std::thread(&Impl::run, &state);
        }
        pid_t pid;
#ifdef LIBMW_PROCESS_TESTING
        if(process_test::faults.before_spawn)
        {
            return std::unexpected(processError("injected setup failure", EIO));
        }
#endif
        code = posix_spawnp(&pid, argv[0], &actions.actions, nullptr,
                            argv.data(), environ);
        if(code)
        {
            return std::unexpected(processError(
                "launch " + owned_args.front(), code));
        }
        state.pid = pid;
#ifdef LIBMW_PROCESS_TESTING
        if(process_test::faults.after_spawn)
        {
            return std::unexpected(processError(
                "injected commit failure", EIO));
        }
#endif
        if(child_input)
        {
            auto closed = child_input->closeOutput();
            if(!closed)
            {
                return std::unexpected(closed.error());
            }
        }
        if(child_output)
        {
            auto closed = child_output->closeInput();
            if(!closed)
            {
                return std::unexpected(closed.error());
            }
        }
        if(state.output)
        {
            state.output->clear();
        }
        {
            std::lock_guard lock(state.mutex);
            state.started = true;
            state.changed.notify_all();
        }
        return process;
    }
    catch(const std::system_error& error)
    {
        return std::unexpected(processError(
            error.what(), error.code().value()));
    }
    catch(const std::exception& error)
    {
        return std::unexpected(processError(error.what(), 0));
    }
}

E<std::optional<ProcessExit>> Process::status()
{
    if(!impl)
    {
        return std::unexpected(processError("Empty process handle", 0));
    }
    if(impl->ownership_error)
    {
        return std::unexpected(*impl->ownership_error);
    }
    if(impl->exit)
    {
        return impl->exit;
    }
    if(impl->pid <= 0)
    {
        return std::unexpected(processError("Child ownership lost", ECHILD));
    }
    for(int attempt = 0; attempt < 8; ++attempt)
    {
        int raw_status;
        pid_t result = queryChild(impl->pid, &raw_status);
        if(result == 0)
        {
            return std::optional<ProcessExit>{};
        }
        if(result == impl->pid)
        {
            impl->pid = 0;
            if(WIFEXITED(raw_status))
            {
                impl->exit = ProcessExit{ProcessExitKind::EXITED,
                                          WEXITSTATUS(raw_status)};
            }
            else
            {
                impl->exit = ProcessExit{ProcessExitKind::SIGNALED, 0,
                    WTERMSIG(raw_status),
                    static_cast<bool>(WCOREDUMP(raw_status))};
            }
            return impl->exit;
        }
        int code = errno;
        if(code == ECHILD)
        {
            impl->pid = 0;
            impl->ownership_error = processError("Child ownership lost", code);
            return std::unexpected(*impl->ownership_error);
        }
        if(code != EINTR)
        {
            return std::unexpected(processError("waitpid child", code));
        }
    }
    return std::unexpected(processError(
        "waitpid repeatedly interrupted", EINTR));
}

E<ProcessWaitResult> Process::waitImpl(Deadline deadline, bool child_only)
{
    if(!impl)
    {
        return std::unexpected(processError("Empty process handle", 0));
    }
    for(;;)
    {
        auto observed = status();
        auto published = impl->publish();
        if(!observed)
        {
            const auto* error = observed.error().as<ProcessError>();
            if(error && error->code == EINTR)
            {
                // status bounds immediate retries; waits retry on the next
                // bounded iteration, preserving the original deadline.
                observed = impl->exit;
            }
        }
        if(!observed)
        {
            return std::unexpected(observed.error());
        }
        if(!published)
        {
            return std::unexpected(published.error());
        }
        std::unique_lock lock(impl->mutex);
        if(impl->io_error)
        {
            return std::unexpected(*impl->io_error);
        }
        if(impl->fallback_error)
        {
            return std::unexpected(processError("Managed I/O exception", 0));
        }
        if(*observed && (child_only || impl->done))
        {
            // The pump may enqueue its final chunk between publication and
            // this check. Publish once more after observing completion.
            bool output_complete = impl->output_complete;
            lock.unlock();
            published = impl->publish();
            if(!published)
            {
                return std::unexpected(published.error());
            }
            return ProcessWaitResult{ProcessWaitState::COMPLETE, *observed,
                                      output_complete};
        }
        if(expired(deadline))
        {
            return ProcessWaitResult{ProcessWaitState::DEADLINE_EXPIRED,
                                      *observed, impl->output_complete};
        }
        auto next = after(std::chrono::milliseconds(10));
        if(deadline)
        {
            next = std::min(next, *deadline);
        }
        impl->changed.wait_until(lock, next);
    }
}

E<ProcessWaitResult> Process::waitUntil(ProcessDeadline deadline)
{
    return waitImpl(deadline, false);
}

E<ProcessWaitResult> Process::waitFor(std::chrono::milliseconds timeout)
{
    if(timeout.count() < 0)
    {
        return std::unexpected(processError("Negative wait duration", 0));
    }
    return waitUntil(after(timeout));
}

E<int> Process::wait()
{
    auto result = waitImpl({}, false);
    if(!result)
    {
        return std::unexpected(result.error());
    }
    if(result->exit->kind == ProcessExitKind::SIGNALED)
    {
        return std::unexpected(processError("Child terminated by signal " +
            std::to_string(result->exit->signal), 0));
    }
    return result->exit->exit_code;
}

E<void> Process::terminate(bool force)
{
    auto observed = status();
    if(!observed)
    {
        return std::unexpected(observed.error());
    }
    if(*observed)
    {
        return {};
    }
    if(::kill(impl->pid, force ? SIGKILL : SIGTERM) < 0)
    {
        int code = errno;
        if(code == ESRCH)
        {
            observed = status();
            if(observed && *observed)
            {
                return {};
            }
            if(!observed)
            {
                return std::unexpected(observed.error());
            }
        }
        return std::unexpected(processError("signal child", code));
    }
    return {};
}

E<ProcessWaitResult> Process::shutdown(std::chrono::milliseconds grace,
                                      ProcessDeadline deadline)
{
    if(grace.count() < 0)
    {
        return std::unexpected(processError("Negative shutdown grace", 0));
    }
    auto observed = status();
    if(!observed)
    {
        if(impl)
        {
            std::ignore = impl->publish();
        }
        return std::unexpected(observed.error());
    }
    if(*observed)
    {
        return waitImpl(deadline, true);
    }
    auto grace_deadline = std::min(after(grace), deadline);
    impl->command(false);
    auto signaled = terminate();
    if(!signaled)
    {
        std::ignore = impl->publish();
        return std::unexpected(signaled.error());
    }
    auto result = waitImpl(grace_deadline, true);
    if(!result || result->state == ProcessWaitState::COMPLETE)
    {
        return result;
    }
    signaled = terminate(true);
    if(!signaled)
    {
        std::ignore = impl->publish();
        return std::unexpected(signaled.error());
    }
    return waitImpl(deadline, true);
}

} // namespace mw
