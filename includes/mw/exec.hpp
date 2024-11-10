// Usage: See the Exec.CanPipeWithPipes and Exec.CanPipeWithString
// unit tests.

#pragma once

#include <array>
#include <initializer_list>
#include <string>
#include <variant>
#include <ranges>

#include "error.hpp"
#include "utils.hpp"

namespace mw
{

// A thin wrapper around the POSIX pipe utilities. Here “input” means
// the end which data flows into the pipe, and “output” means the end
// which data flows out of the pipe.
class Pipe
{
public:
    // Do not use. Does not actually do anything.
    Pipe() = default;
    Pipe(const Pipe&) = delete;
    Pipe(Pipe&& rhs);
    Pipe& operator=(const Pipe&) = delete;
    Pipe& operator=(Pipe&& rhs);

    static E<Pipe> create();

    // This class does not keep track of duped FDs. If you have
    // duplicateded an end, destroying the Pipe object does not always
    // mean the destruction of the actual pipe.
    ~Pipe();

    E<void> closeInput();
    E<void> closeOutput();
    E<int> dupInput(int fd) const;
    E<int> dupOutput(int fd) const;

    int inputFD() const { return fds[1]; }
    int outputFD() const { return fds[0]; }

    E<std::string> read() const;
    E<void> write(std::string_view data) const;

private:
    // an array that will hold two file descriptors
    std::array<int, 2> fds = {-1, -1};
    bool output_closed = true;
    bool input_closed = true;
};

// Doesn’t support using a pipe to connect two Processes yet.
struct Process
{
public:
    using None = std::nullptr_t;
    using Input = std::variant<None, std::string_view, Pipe*>;
    using Output = std::variant<None, std::string*, Pipe*>;
    // Do not use. Does not actually do anything.
    Process() = default;
    // Start a child process with “args”.
    template<std::ranges::input_range Range =
             std::initializer_list<const char*>>
    requires std::ranges::common_range<Range> &&
      std::convertible_to<std::ranges::range_value_t<Range>, const char*>
    static E<Process> exec(const Input input, Range&& args,
                           const Output output);

    Process(const Process&) = delete;
    Process(Process&& rhs);
    Process& operator=(const Process&) = delete;
    Process& operator=(Process&& rhs);

    ~Process();

    // Wait for the child process to finish. Obviously this must be
    // called after calling exec(). Also it must be called exactly
    // once.
    E<int> wait();

private:
    // Stores the PID of the child.
    pid_t pid = 0;
    // This is used to let the child tell the parent when execvp
    // fails. This could probably be replaced with either shard mem or
    // a message queue.
    Pipe comm;
    // Save the output parameter of the exec() call, so that the
    // output pipe/string can be manipulated in wait().
    Output output = nullptr;
    // If the output is a string, we will use this to pipe the output
    // to the string.
    Pipe managed_output_pipe;
};

// ====== Template implementations ==================================>

template<std::ranges::input_range Range>
requires std::ranges::common_range<Range> &&
std::convertible_to<std::ranges::range_value_t<Range>, const char*>
E<Process> Process::exec(
    const Input input, Range&& args,
    const Output output)
{
    Process proc;
    Pipe input_pipe;
    proc.output = output;
    if(std::holds_alternative<std::string_view>(input))
    {
        ASSIGN_OR_RETURN(input_pipe, Pipe::create());
    }
    if(std::holds_alternative<std::string*>(output))
    {
        ASSIGN_OR_RETURN(proc.managed_output_pipe, Pipe::create());
    }

    ASSIGN_OR_RETURN(proc.comm, Pipe::create());

    pid_t pid = fork(); // create child process that is a clone of the parent
    if(pid == 0)       // if pid == 0, then this is the child process
    {
        if(std::holds_alternative<Pipe*>(input))
        {
            Pipe* input_pipe = std::get<Pipe*>(input);
            DO_OR_RETURN(input_pipe->dupOutput(STDIN_FILENO));
            DO_OR_RETURN(input_pipe->closeOutput());
            DO_OR_RETURN(input_pipe->closeInput());
        }
        else if(std::holds_alternative<std::string_view>(input))
        {
            DO_OR_RETURN(input_pipe.dupOutput(STDIN_FILENO));
            DO_OR_RETURN(input_pipe.closeOutput());
            DO_OR_RETURN(input_pipe.closeInput());
        }

        if(std::holds_alternative<Pipe*>(output))
        {
            Pipe* output_pipe = std::get<Pipe*>(output);
            DO_OR_RETURN(output_pipe->dupInput(STDOUT_FILENO));
            // file descriptor no longer needed in child since stdin is a copy.
            DO_OR_RETURN(output_pipe->closeInput());
            // file descriptor unused in child.
            DO_OR_RETURN(output_pipe->closeOutput());
        }
        else if(std::holds_alternative<std::string*>(output))
        {
            DO_OR_RETURN(proc.managed_output_pipe.dupInput(STDOUT_FILENO));
            // file descriptor no longer needed in child since stdin is a copy.
            DO_OR_RETURN(proc.managed_output_pipe.closeInput());
            // file descriptor unused in child.
            DO_OR_RETURN(proc.managed_output_pipe.closeOutput());
        }

        DO_OR_RETURN(proc.comm.closeOutput());

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        std::ranges::for_each(args, [&argv](const char* arg)
        {
            argv.push_back(const_cast<char*>(arg));
        });
        argv.push_back(nullptr);
        if(execvp(argv[0], reinterpret_cast<char* const*>(argv.data())) < 0)
        {
            proc.comm.write("FAIL");
            proc.comm.closeInput();
            exit(1);
        }
        std::unreachable();
    }

    // if we reach here, we are in parent process
    if(std::holds_alternative<Pipe*>(input))
    {
        DO_OR_RETURN(std::get<Pipe*>(input)->closeOutput());
    }
    else if(std::holds_alternative<std::string_view>(input))
    {
        input_pipe.closeOutput();
        input_pipe.write(std::get<std::string_view>(input));
        input_pipe.closeInput();
    }

    if(std::holds_alternative<Pipe*>(output))
    {
        DO_OR_RETURN(std::get<Pipe*>(output)->closeInput());
    }
    else if(std::holds_alternative<std::string*>(output))
    {
        DO_OR_RETURN(proc.managed_output_pipe.closeInput());
    }

    DO_OR_RETURN(proc.comm.closeInput());
    proc.pid = pid;
    return E<Process>{std::in_place, std::move(proc)};
}

} // namespace mw
