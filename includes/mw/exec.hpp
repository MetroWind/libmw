#pragma once

#include <array>
#include <chrono>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "error.hpp"

namespace mw
{

/// A monotonic absolute time limit for an operation.
using ProcessDeadline = std::chrono::steady_clock::time_point;

/// The reason pipe I/O stopped.
enum class PipeState
{
    /// A read produced data, or all requested bytes were written.
    COMPLETE,
    /// The read end reached EOF after draining buffered bytes.
    EOF_REACHED,
    /// An immediate read found no available bytes.
    WOULD_BLOCK,
    /// The absolute time budget expired.
    DEADLINE_EXPIRED,
};

/// A single chunk, with no protocol framing significance.
struct PipeReadResult
{
    /// Only COMPLETE contains data; the other states contain no bytes.
    PipeState state;
    /// Arbitrary bytes, including embedded NULs.
    std::string data;
};

/// The accepted prefix of a write, which must never be replayed.
struct PipeWriteResult
{
    /// COMPLETE or DEADLINE_EXPIRED.
    PipeState state;
    /// Bytes accepted by the kernel, not necessarily consumed by the peer.
    size_t bytes_written;
};

/// An operational failure, with saved errno and per-call I/O progress.
struct ProcessError
{
    /// Operation and context.
    std::string msg;
    /// OS error number, or zero for validation failures.
    int code;
    /// Bytes transferred before failure.
    size_t bytes_transferred = 0;
};

/// How the direct child terminated.
enum class ProcessExitKind
{
    /// The child exited normally, possibly with a nonzero code.
    EXITED,
    /// A signal terminated the child.
    SIGNALED,
};

/// Cached, immutable termination status.
struct ProcessExit
{
    /// Determines which numeric status is meaningful.
    ProcessExitKind kind;
    /// Normal exit code, including nonzero codes.
    int exit_code = 0;
    /// Terminating signal when kind is SIGNALED.
    int signal = 0;
    /// Whether the wait status indicates a core dump.
    bool core_dumped = false;
};

/// Whether the requested lifecycle condition was met.
enum class ProcessWaitState
{
    /// The method's completion condition was met.
    COMPLETE,
    /// The budget expired; ownership and I/O progress remain resumable.
    DEADLINE_EXPIRED,
};

/// Lifecycle and capture state are independent.
struct ProcessWaitResult
{
    /// waitUntil requires child exit and managed I/O; shutdown only exit.
    ProcessWaitState state;
    /// Present as soon as the direct child is reaped.
    std::optional<ProcessExit> exit;
    /// Capture reached EOF, or no capture was requested.
    bool output_complete = false;
};

/// Owning POSIX pipe. Input is the write end; output is the read end.
/// One reader and one writer may run concurrently. Close requires the
/// affected operation to have returned; move/destruction require all I/O
/// to have returned. Raw borrowers and duplicates obey the same rules.
class Pipe
{
public:
    /// Construct an empty pipe.
    Pipe() = default;
    /// Pipes have exactly one endpoint owner and cannot be copied.
    Pipe(const Pipe&) = delete;
    /// Transfer endpoints and invalidate the source.
    Pipe(Pipe&& rhs) noexcept;
    /// Copy assignment cannot duplicate endpoint ownership.
    Pipe& operator=(const Pipe&) = delete;
    /// Close destination endpoints, then transfer; self-move is harmless.
    Pipe& operator=(Pipe&& rhs) noexcept;
    /// Close owned endpoints without throwing; duplicates remain owned
    /// by their borrowers.
    ~Pipe() noexcept;
    /// Atomically create blocking, close-on-exec endpoints.
    static E<Pipe> create();
    /// Close the write end; repeated closure succeeds.
    E<void> closeInput();
    /// Close the read end; repeated closure succeeds.
    E<void> closeOutput();
    /// Duplicate the write end. Library I/O permanently sets O_NONBLOCK
    /// on this endpoint and its duplicates.
    E<int> dupInput(int fd) const;
    /// Duplicate the read end, sharing its permanent nonblocking flag.
    E<int> dupOutput(int fd) const;
    /// Borrow the write end. Configure before concurrent external use;
    /// borrowers must not change flags during library I/O.
    int inputFD() const { return fds[1]; }
    /// Borrow the read end, with the same flag/lifetime rules as inputFD.
    int outputFD() const { return fds[0]; }
    /// Read to EOF, without a deadline.
    E<std::string> read() const;
    /// Write all bytes, without a deadline; errors retain prefix progress.
    /// SIGPIPE masking is local to the thread and preserves pending signals.
    /// Concurrent unrelated SIGPIPE injection cannot be distinguished.
    E<void> write(std::string_view data) const;
    /// Immediately read a chunk, EOF, or WOULD_BLOCK. Zero size is invalid.
    E<PipeReadResult> tryRead(size_t max_bytes = 65536) const;
    /// Read one chunk or EOF until a monotonic absolute deadline.
    E<PipeReadResult> readChunk(size_t max_bytes,
                                ProcessDeadline deadline) const;
    /// Write until completion or deadline, preserving accepted progress.
    /// An expired deadline still permits one immediate nonblocking attempt.
    E<PipeWriteResult> writeUntil(std::string_view data,
                                  ProcessDeadline deadline) const;
private:
    std::array<int, 2> fds = {-1, -1};
    mutable std::array<std::mutex, 2> setup_mutex;
    E<void> prepare(size_t endpoint) const;
};

/// Exactly one owner of a direct child. Serialize lifecycle calls.
/// No competing reaper or SIGCHLD auto-reaping is supported. Environment
/// mutation during launch is unsupported. Descendants are not terminated.
struct Process
{
    /// Inherit the corresponding standard stream.
    using None = std::nullptr_t;
    /// Inherit stdin, copy string input, or consume a pipe's read end.
    using Input = std::variant<None, std::string_view, Pipe*>;
    /// Inherit stdout, capture to a string, or use a pipe's write end.
    /// A capture string must outlive this handle and lifecycle calls;
    /// do not access or modify it during publication by lifecycle calls.
    using Output = std::variant<None, std::string*, Pipe*>;
    /// Construct an empty handle; lifecycle operations report validation.
    Process() noexcept;
    /// A direct child cannot have two lifecycle owners.
    Process(const Process&) = delete;
    /// Transfer ownership, leaving the source empty.
    Process(Process&& rhs) noexcept;
    /// Copy assignment cannot duplicate child ownership.
    Process& operator=(const Process&) = delete;
    /// Kill/reap the destination before transferring ownership.
    Process& operator=(Process&& rhs) noexcept;
    /// Kill/reap a live child, cancel and join managed I/O, without throwing.
    /// Kernel uninterruptible work can delay even forced cleanup.
    ~Process() noexcept;

    /// Launch directly, with length-aware argv and synchronous launch errors.
    /// Reject NULs, invalid endpoints and nonblocking child endpoints (use
    /// a fresh pipe). Parent child-facing endpoints close on success;
    /// post-spawn failure may leave those endpoints closed.
    static E<Process> execArgs(Input input,
                              std::span<const std::string_view> args,
                              Output output);
    /// C-string adapter; bytes past the first NUL cannot be validated.
    /// String input is copied and delivered asynchronously after launch.
    template<std::ranges::input_range Range =
             std::initializer_list<const char*>>
    requires std::ranges::common_range<Range> &&
        std::convertible_to<std::ranges::range_value_t<Range>, const char*>
    static E<Process> exec(Input input, Range&& args, Output output)
    {
        try
        {
            std::vector<std::string> owned_args;
            for(const char* arg: args)
            {
                if(!arg)
                {
                    return std::unexpected(ProcessError{
                        "Null process argument", 0});
                }
                owned_args.emplace_back(arg);
            }
            std::vector<std::string_view> views;
            for(const auto& arg: owned_args)
            {
                views.emplace_back(arg);
            }
            return execArgs(input, views, output);
        }
        catch(const std::exception& error)
        {
            return std::unexpected(ProcessError{error.what(), 0});
        }
    }
    /// Query only child status, without waiting for capture or I/O errors.
    E<std::optional<ProcessExit>> status();
    /// Wait for child exit and managed I/O; timeouts preserve ownership and
    /// publish partial capture. Repeated completed waits return cached status.
    E<ProcessWaitResult> waitUntil(ProcessDeadline deadline);
    /// Convert a nonnegative relative budget once, saturating on overflow.
    E<ProcessWaitResult> waitFor(std::chrono::milliseconds timeout);
    /// Unlimited wait; normal exit codes succeed, signal exits are errors.
    E<int> wait();
    /// Request SIGTERM (or SIGKILL), without closing external pipes.
    E<void> terminate(bool force = false);
    /// Stop managed input, send SIGTERM, then escalate after grace.
    /// Completion requires only direct-child reaping, not capture EOF.
    /// For EOF-first shutdown, close external stdin and waitFor first.
    E<ProcessWaitResult> shutdown(std::chrono::milliseconds grace,
                                 ProcessDeadline deadline);
private:
    struct Impl;
    std::unique_ptr<Impl> impl;
    E<ProcessWaitResult> waitImpl(std::optional<ProcessDeadline> deadline,
                                 bool child_only);
};

} // namespace mw
