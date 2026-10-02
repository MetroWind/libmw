#include <array>
#include <initializer_list>
#include <string>
#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <future>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include "exec.hpp"
#include "process_test_hooks.hpp"
#include <cstring>
#include "test_utils.hpp"

namespace mw
{

TEST(Exec, CanPipeWithPipes)
{
    ASSIGN_OR_FAIL(Pipe input, Pipe::create());
    ASSIGN_OR_FAIL(auto output_pipe, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input, {"cat",}, &output_pipe));
    EXPECT_TRUE(isExpected(input.write("aaa")));
    EXPECT_TRUE(isExpected(input.closeInput()));
    ASSIGN_OR_FAIL(std::string output, output_pipe.read());
    EXPECT_TRUE(isExpected(output_pipe.closeOutput()));
    EXPECT_EQ(output, "aaa");
    ASSIGN_OR_FAIL(int status, proc.wait());
    EXPECT_EQ(status, 0);
}

TEST(Exec, CanPipeWithString)
{
    std::string output;
    ASSIGN_OR_FAIL(auto proc, Process::exec("aaa", {"cat",}, &output));
    ASSIGN_OR_FAIL(int status, proc.wait());
    EXPECT_EQ(output, "aaa");
    EXPECT_EQ(status, 0);
}

TEST(Exec, CanPipeBetweenProcs)
{
    std::string output;
    ASSIGN_OR_FAIL(Pipe ipc, Pipe::create());
    ASSIGN_OR_FAIL(Process proc1, Process::exec("bbb\naaa", {"cat",}, &ipc));
    ASSIGN_OR_FAIL(Process proc2, Process::exec(&ipc, {"sort",}, &output));
    ASSIGN_OR_FAIL(int status1, proc1.wait());
    ASSIGN_OR_FAIL(int status2, proc2.wait());
    EXPECT_EQ(output, "aaa\nbbb\n");
    EXPECT_EQ(status1, 0);
    EXPECT_EQ(status2, 0);
}

TEST(Exec, CanStartConsumerBeforeProducer)
{
    std::string output;
    ASSIGN_OR_FAIL(Pipe ipc, Pipe::create());
    ASSIGN_OR_FAIL(Process consumer,
                   Process::exec(&ipc, {"cat"}, &output));
    ASSIGN_OR_FAIL(Process producer,
                   Process::exec("aaa", {"cat"}, &ipc));
    ASSIGN_OR_FAIL(int consumer_status, consumer.wait());
    ASSIGN_OR_FAIL(int producer_status, producer.wait());
    EXPECT_EQ(output, "aaa");
    EXPECT_EQ(consumer_status, 0);
    EXPECT_EQ(producer_status, 0);
}

TEST(Exec, CanPipeLargeOutputThroughThreeProcs)
{
    std::string output;
    ASSIGN_OR_FAIL(Pipe first_pipe, Pipe::create());
    ASSIGN_OR_FAIL(Pipe second_pipe, Pipe::create());
    ASSIGN_OR_FAIL(Process producer, Process::exec(
        nullptr, {"head", "-c", "262144", "/dev/zero"}, &first_pipe));
    ASSIGN_OR_FAIL(Process middle,
                   Process::exec(&first_pipe, {"cat"}, &second_pipe));
    ASSIGN_OR_FAIL(Process consumer,
                   Process::exec(&second_pipe, {"cat"}, &output));
    ASSIGN_OR_FAIL(int consumer_status, consumer.wait());
    ASSIGN_OR_FAIL(int middle_status, middle.wait());
    ASSIGN_OR_FAIL(int producer_status, producer.wait());
    EXPECT_EQ(output, std::string(262144, '\0'));
    EXPECT_EQ(consumer_status, 0);
    EXPECT_EQ(middle_status, 0);
    EXPECT_EQ(producer_status, 0);
}

TEST(Exec, UnrelatedProcessDoesNotKeepPipelineOpen)
{
    std::string output;
    ASSIGN_OR_FAIL(Pipe ipc, Pipe::create());
    ASSIGN_OR_FAIL(Pipe unrelated_input, Pipe::create());
    ASSIGN_OR_FAIL(Process unrelated,
                   Process::exec(&unrelated_input, {"cat"}, nullptr));
    ASSIGN_OR_FAIL(Process producer,
                   Process::exec("aaa", {"cat"}, &ipc));
    ASSIGN_OR_FAIL(Process consumer,
                   Process::exec(&ipc, {"cat"}, &output));
    // The unrelated process is still waiting for input when the pipeline
    // reaches EOF. It must not retain a copy of ipc's write end.
    ASSIGN_OR_FAIL(int consumer_status, consumer.wait());
    ASSIGN_OR_FAIL(int producer_status, producer.wait());
    ASSERT_TRUE(isExpected(unrelated_input.closeInput()));
    ASSIGN_OR_FAIL(int unrelated_status, unrelated.wait());
    EXPECT_EQ(output, "aaa");
    EXPECT_EQ(consumer_status, 0);
    EXPECT_EQ(producer_status, 0);
    EXPECT_EQ(unrelated_status, 0);
}

TEST(Exec, WillFailWithInvalidCmd)
{
    ASSIGN_OR_FAIL(Pipe input, Pipe::create());
    ASSIGN_OR_FAIL(auto output_pipe, Pipe::create());
    auto proc = Process::exec(&input, {"fjdkal",}, &output_pipe);
    ASSERT_FALSE(proc);
    ASSERT_NE(proc.error().as<ProcessError>(), nullptr);
    EXPECT_EQ(proc.error().as<ProcessError>()->code, ENOENT);
    EXPECT_GE(input.outputFD(), 0);
    EXPECT_GE(output_pipe.inputFD(), 0);
}

TEST(Exec, CanUseContainerAsArgs)
{
    std::array<const char*, 2> args = {"true", "1"};
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr, args, nullptr));
    EXPECT_TRUE(isExpected(proc.wait()));
}


namespace
{
using namespace std::chrono_literals;
using TestClock = std::chrono::steady_clock;

E<std::string> receive(const Pipe& pipe, size_t size)
{
    std::string result;
    auto deadline = TestClock::now() + 3s;
    while(result.size() < size)
    {
        auto chunk = pipe.readChunk(size - result.size(), deadline);
        if(!chunk)
        {
            return std::unexpected(chunk.error());
        }
        if(chunk->state != PipeState::COMPLETE)
        {
            return std::unexpected(runtimeError("Incomplete helper reply"));
        }
        result += chunk->data;
    }
    return result;
}

size_t countDescriptors()
{
    size_t count = 0;
    for([[maybe_unused]] const auto& entry:
        std::filesystem::directory_iterator("/proc/self/fd"))
    {
        ++count;
    }
    return count;
}

void harmlessSignal(int) {}

int brokenPipeCase(int disposition, bool blocked, bool pending)
{
    struct sigaction action{};
    action.sa_handler = disposition == 0 ? SIG_DFL :
        (disposition == 1 ? SIG_IGN : harmlessSignal);
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, nullptr);
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(blocked ? SIG_BLOCK : SIG_UNBLOCK, &mask, nullptr);
    if(pending)
    {
        raise(SIGPIPE);
    }
    auto pipe = Pipe::create();
    if(!pipe || !pipe->closeOutput())
    {
        return 1;
    }
    auto result = pipe->write("broken");
    if(result || !result.error().as<ProcessError>() ||
       result.error().as<ProcessError>()->code != EPIPE)
    {
        return 2;
    }
    sigset_t after_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &after_mask);
    sigset_t after_pending;
    sigpending(&after_pending);
    struct sigaction after_action{};
    sigaction(SIGPIPE, nullptr, &after_action);
    if(sigismember(&after_mask, SIGPIPE) != static_cast<int>(blocked) ||
       sigismember(&after_pending, SIGPIPE) != static_cast<int>(pending) ||
       after_action.sa_handler != action.sa_handler)
    {
        return 3;
    }
    return 0;
}
}

TEST(Exec, StreamsBinaryRepliesBeforeEof)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input,
        {PROCESS_TEST_HELPER, "echo"}, &output));
    for(int i = 0; i < 3; ++i)
    {
        std::string message("a\0b\n", 4);
        ASSIGN_OR_FAIL(auto written,
            input.writeUntil(message, TestClock::now() + 1s));
        EXPECT_EQ(written.bytes_written, message.size());
        ASSIGN_OR_FAIL(auto reply, receive(output, message.size()));
        EXPECT_EQ(reply, message);
        ASSIGN_OR_FAIL(auto observed, proc.status());
        EXPECT_FALSE(observed);
    }
    ASSERT_TRUE(input.closeInput());
    ASSIGN_OR_FAIL(auto eof, output.readChunk(64, TestClock::now() + 1s));
    EXPECT_EQ(eof.state, PipeState::EOF_REACHED);
    ASSIGN_OR_FAIL(auto done, proc.waitFor(1s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
}

TEST(Exec, IdleReadAndWaitAreResumable)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input,
        {PROCESS_TEST_HELPER, "echo"}, &output));
    ASSIGN_OR_FAIL(auto idle, output.tryRead());
    EXPECT_EQ(idle.state, PipeState::WOULD_BLOCK);
    auto start = TestClock::now();
    ASSIGN_OR_FAIL(auto timeout, output.readChunk(64, start + 40ms));
    EXPECT_EQ(timeout.state, PipeState::DEADLINE_EXPIRED);
    EXPECT_LT(TestClock::now() - start, 2s);
    ASSIGN_OR_FAIL(auto waiting, proc.waitFor(20ms));
    EXPECT_EQ(waiting.state, ProcessWaitState::DEADLINE_EXPIRED);
    EXPECT_FALSE(waiting.exit);
    ASSERT_TRUE(input.write("later"));
    ASSIGN_OR_FAIL(auto reply, receive(output, 5));
    EXPECT_EQ(reply, "later");
    ASSERT_TRUE(input.closeInput());
    ASSIGN_OR_FAIL(auto done, proc.waitFor(1s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
}

TEST(Pipe, DeadlinePreservesExactAcceptedPrefix)
{
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    std::string request(1024 * 1024, 'p');
    ASSIGN_OR_FAIL(auto result,
        pipe.writeUntil(request, TestClock::now() + 20ms));
    EXPECT_EQ(result.state, PipeState::DEADLINE_EXPIRED);
    EXPECT_GT(result.bytes_written, 0u);
    EXPECT_LT(result.bytes_written, request.size());
    ASSERT_TRUE(pipe.closeInput());
    ASSIGN_OR_FAIL(auto received, pipe.read());
    EXPECT_EQ(received, request.substr(0, result.bytes_written));
}

TEST(Pipe, ImmediateOperationsAndValidation)
{
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    EXPECT_NE(fcntl(pipe.inputFD(), F_GETFD) & FD_CLOEXEC, 0);
    EXPECT_NE(fcntl(pipe.outputFD(), F_GETFD) & FD_CLOEXEC, 0);
    EXPECT_FALSE(pipe.tryRead(0));
    EXPECT_EQ(fcntl(pipe.outputFD(), F_GETFL) & O_NONBLOCK, 0);
    ASSIGN_OR_FAIL(auto empty, pipe.writeUntil("", TestClock::now()));
    EXPECT_EQ(empty.state, PipeState::COMPLETE);
    EXPECT_EQ(empty.bytes_written, 0u);
    ASSERT_TRUE(pipe.write("available"));
    ASSERT_TRUE(pipe.closeInput());
    ASSIGN_OR_FAIL(auto data, pipe.readChunk(32, TestClock::now() - 1s));
    EXPECT_EQ(data.data, "available");
    ASSIGN_OR_FAIL(auto eof, pipe.readChunk(32, TestClock::now() - 1s));
    EXPECT_EQ(eof.state, PipeState::EOF_REACHED);
    ASSERT_TRUE(pipe.closeOutput());
    ASSERT_TRUE(pipe.closeOutput());
    EXPECT_FALSE(pipe.tryRead());
    EXPECT_FALSE(pipe.write(""));
}

TEST(Pipe, SigpipeMaskDispositionAndPendingSignalsArePreserved)
{
    EXPECT_EXIT(_exit(brokenPipeCase(0, false, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(1, false, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(2, false, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(0, true, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(0, true, true)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(1, true, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(2, true, false)),
                ::testing::ExitedWithCode(0), "");
    EXPECT_EXIT(_exit(brokenPipeCase(2, true, true)),
                ::testing::ExitedWithCode(0), "");
}

TEST(Exec, ClosedChildInputReportsEpipe)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input,
        {PROCESS_TEST_HELPER, "close_stdin"}, &output));
    ASSIGN_OR_FAIL(auto handshake, receive(output, 5));
    EXPECT_EQ(handshake, "ready");
    auto result = input.writeUntil("request", TestClock::now() + 1s);
    ASSERT_FALSE(result);
    ASSERT_NE(result.error().as<ProcessError>(), nullptr);
    EXPECT_EQ(result.error().as<ProcessError>()->code, EPIPE);
    EXPECT_EQ(result.error().as<ProcessError>()->bytes_transferred, 0u);
    ASSIGN_OR_FAIL(auto done, proc.shutdown(0ms, TestClock::now() + 1s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
}

TEST(Exec, ExitKindsAndRepeatedWaits)
{
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "exit", "127"}, nullptr));
    ASSIGN_OR_FAIL(auto done, proc.waitFor(2s));
    ASSERT_TRUE(done.exit);
    EXPECT_EQ(done.exit->kind, ProcessExitKind::EXITED);
    EXPECT_EQ(done.exit->exit_code, 127);
    ASSIGN_OR_FAIL(auto again, proc.waitFor(0ms));
    EXPECT_EQ(again.state, ProcessWaitState::COMPLETE);
    ASSIGN_OR_FAIL(auto legacy, proc.wait());
    EXPECT_EQ(legacy, 127);
    ASSERT_TRUE(proc.terminate());
    ASSIGN_OR_FAIL(auto shutdown, proc.shutdown(0ms, TestClock::now()));
    EXPECT_EQ(shutdown.exit->exit_code, 127);
    ASSIGN_OR_FAIL(auto signaled, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "signal"}, nullptr));
    ASSIGN_OR_FAIL(auto signal_exit, signaled.waitFor(2s));
    ASSERT_TRUE(signal_exit.exit);
    EXPECT_EQ(signal_exit.exit->kind, ProcessExitKind::SIGNALED);
    EXPECT_EQ(signal_exit.exit->signal, SIGTERM);
    EXPECT_FALSE(signaled.wait());
    ASSERT_TRUE(signaled.terminate(true));
}

TEST(Exec, ValidatesLaunchAndPreservesPipesOnFailure)
{
    EXPECT_FALSE(Process::exec(nullptr, {}, nullptr));
    EXPECT_FALSE(Process::exec(nullptr, {""}, nullptr));
    EXPECT_FALSE(Process::exec(nullptr, {nullptr}, nullptr));
    std::string embedded("echo\0hidden", 11);
    std::array<std::string_view, 1> args{embedded};
    EXPECT_FALSE(Process::execArgs(nullptr, args, nullptr));
    EXPECT_FALSE(Process::exec(static_cast<Pipe*>(nullptr),
        {PROCESS_TEST_HELPER, "exit"}, nullptr));
    EXPECT_FALSE(Process::exec(nullptr, {PROCESS_TEST_HELPER, "exit"},
        static_cast<std::string*>(nullptr)));
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    ASSERT_TRUE(pipe.tryRead());
    EXPECT_FALSE(Process::exec(&pipe,
        {PROCESS_TEST_HELPER, "exit"}, nullptr));
    EXPECT_GE(pipe.outputFD(), 0);
    EXPECT_GE(pipe.inputFD(), 0);
    EXPECT_FALSE(Process::exec(&pipe,
        {PROCESS_TEST_HELPER, "echo"}, &pipe));
    Process empty;
    EXPECT_FALSE(empty.status());
    EXPECT_FALSE(empty.waitFor(0ms));
    EXPECT_FALSE(empty.terminate());
    EXPECT_FALSE(empty.shutdown(0ms, TestClock::now()));
    EXPECT_FALSE(empty.waitFor(-1ms));
}

TEST(Exec, ExecutableFormatAndPermissionFailuresAreSynchronous)
{
    char path[] = "/tmp/libmw_launch_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::write(fd, "not executable\n", 15), 15);
    ASSERT_EQ(fchmod(fd, 0700), 0);
    ::close(fd);
    auto format = Process::exec(nullptr, {path}, nullptr);
    ASSERT_FALSE(format);
    EXPECT_EQ(format.error().as<ProcessError>()->code, ENOEXEC);
    ASSERT_EQ(chmod(path, 0600), 0);
    auto permission = Process::exec(nullptr, {path}, nullptr);
    ASSERT_FALSE(permission);
    EXPECT_EQ(permission.error().as<ProcessError>()->code, EACCES);
    unlink(path);
}

TEST(Exec, LargeManagedDuplexDoesNotDeadlock)
{
    std::string input(1024 * 1024, 'i');
    std::string output = "old";
    ASSIGN_OR_FAIL(auto proc, Process::exec(input,
        {PROCESS_TEST_HELPER, "duplex"}, &output));
    EXPECT_TRUE(output.empty());
    ASSIGN_OR_FAIL(auto done, proc.waitFor(5s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
    EXPECT_TRUE(done.output_complete);
    EXPECT_EQ(output, std::string(1024 * 1024, 'x') + input);
    auto saved = output;
    ASSIGN_OR_FAIL(auto again, proc.waitFor(0ms));
    EXPECT_EQ(again.state, ProcessWaitState::COMPLETE);
    EXPECT_EQ(output, saved);
}

TEST(Exec, ShutdownEscalatesAndPreservesTimedOwnership)
{
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "ignore"}, &output));
    ASSIGN_OR_FAIL(auto handshake, receive(output, 5));
    EXPECT_EQ(handshake, "ready");
    ASSIGN_OR_FAIL(auto done, proc.shutdown(30ms, TestClock::now() + 2s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
    ASSERT_TRUE(done.exit);
    EXPECT_EQ(done.exit->signal, SIGKILL);
    ASSIGN_OR_FAIL(auto second, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "idle"}, nullptr));
    ASSIGN_OR_FAIL(auto immediate, second.shutdown(0ms, TestClock::now()));
    EXPECT_TRUE(immediate.exit ||
        immediate.state == ProcessWaitState::DEADLINE_EXPIRED);
    ASSIGN_OR_FAIL(auto reaped, second.waitFor(2s));
    EXPECT_EQ(reaped.state, ProcessWaitState::COMPLETE);
}

TEST(Exec, DescendantCaptureDoesNotHideDirectChildExit)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    std::string output;
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input,
        {PROCESS_TEST_HELPER, "descendant"}, &output));
    ASSIGN_OR_FAIL(auto timed, proc.waitFor(200ms));
    EXPECT_EQ(timed.state, ProcessWaitState::DEADLINE_EXPIRED);
    ASSERT_TRUE(timed.exit);
    EXPECT_EQ(timed.exit->exit_code, 0);
    EXPECT_FALSE(timed.output_complete);
    EXPECT_EQ(output, "ready");
    ASSIGN_OR_FAIL(auto done, proc.shutdown(0ms, TestClock::now()));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
    EXPECT_FALSE(done.output_complete);
    ASSERT_TRUE(input.closeInput());
    ASSIGN_OR_FAIL(auto capture, proc.waitFor(2s));
    EXPECT_EQ(capture.state, ProcessWaitState::COMPLETE);
    EXPECT_TRUE(capture.output_complete);
    EXPECT_EQ(output, "ready");
}

TEST(Exec, DestroyAndMoveOverActiveChildrenReapOnlyOwnedPids)
{
    pid_t unrelated = fork();
    ASSERT_GE(unrelated, 0);
    if(unrelated == 0)
    {
        _exit(42);
    }
    ASSIGN_OR_FAIL(auto first, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "idle"}, nullptr));
    ASSIGN_OR_FAIL(auto second, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "idle"}, nullptr));
    second = std::move(first);
    EXPECT_FALSE(first.status());
    auto& same = second;
    second = std::move(same);
    Process moved(std::move(second));
    EXPECT_FALSE(second.status());
    moved = Process{};
    int raw_status;
    EXPECT_EQ(waitpid(unrelated, &raw_status, 0), unrelated);
    EXPECT_EQ(WEXITSTATUS(raw_status), 42);
    // All helper children were reaped; no libmw zombie remains.
    EXPECT_EQ(waitpid(-1, &raw_status, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
}

TEST(Exec, DestructionCancelsCaptureWithoutDescendantEof)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    std::string output;
    auto start = TestClock::now();
    {
        ASSIGN_OR_FAIL(auto proc, Process::exec(&input,
            {PROCESS_TEST_HELPER, "descendant"}, &output));
        ASSIGN_OR_FAIL(auto timed, proc.waitFor(100ms));
        ASSERT_TRUE(timed.exit);
        ASSERT_FALSE(timed.output_complete);
    }
    EXPECT_LT(TestClock::now() - start, 2s);
    ASSERT_TRUE(input.closeInput());
}

TEST(Exec, StandardDescriptorCollisions)
{
    EXPECT_EXIT({
        close(0);
        close(1);
        close(2);
        auto input = Pipe::create();
        auto output = Pipe::create();
        if(!input || !output)
        {
            _exit(1);
        }
        auto proc = Process::exec(&*input,
            {PROCESS_TEST_HELPER, "echo"}, &*output);
        if(!proc || !input->write("collision") || !input->closeInput())
        {
            _exit(2);
        }
        auto reply = receive(*output, 9);
        auto done = proc->waitFor(2s);
        _exit(reply && *reply == "collision" && done && done->exit ? 0 : 3);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(Pipe, InterruptedReadKeepsItsDeadline)
{
    struct sigaction action{};
    action.sa_handler = harmlessSignal;
    sigemptyset(&action.sa_mask);
    struct sigaction saved{};
    ASSERT_EQ(sigaction(SIGUSR1, &action, &saved), 0);
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    std::promise<pthread_t> reader_id;
    auto id = reader_id.get_future();
    std::promise<E<PipeReadResult>> promise;
    auto result = promise.get_future();
    std::thread reader([&]
    {
        reader_id.set_value(pthread_self());
        promise.set_value(pipe.readChunk(64, TestClock::now() + 100ms));
    });
    auto target = id.get();
    for(int i = 0; i < 20; ++i)
    {
        pthread_kill(target, SIGUSR1);
        std::this_thread::sleep_for(2ms);
    }
    reader.join();
    ASSERT_EQ(sigaction(SIGUSR1, &saved, nullptr), 0);
    ASSIGN_OR_FAIL(auto timed, result.get());
    EXPECT_EQ(timed.state, PipeState::DEADLINE_EXPIRED);
    ASSERT_TRUE(pipe.write("later"));
    ASSIGN_OR_FAIL(auto later, receive(pipe, 5));
    EXPECT_EQ(later, "later");
}

TEST(Exec, ConcurrentLaunchIoAndCleanup)
{
    std::atomic<bool> success = true;
    std::vector<std::thread> workers;
    for(int i = 0; i < 8; ++i)
    {
        workers.emplace_back([&]
        {
            for(int j = 0; j < 10; ++j)
            {
                std::string output;
                std::string input(32768, 't');
                auto proc = Process::exec(input,
                    {PROCESS_TEST_HELPER, "echo"}, &output);
                if(!proc)
                {
                    success = false;
                    continue;
                }
                auto done = proc->waitFor(3s);
                if(!done || done->state != ProcessWaitState::COMPLETE ||
                   output != input)
                {
                    success = false;
                }
            }
        });
    }
    for(auto& worker: workers)
    {
        worker.join();
    }
    EXPECT_TRUE(success);
}


TEST(Exec, InjectedSpawnFailuresRollbackResources)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    process_test::faults.before_spawn = true;
    auto before = Process::exec(&input,
        {PROCESS_TEST_HELPER, "idle"}, &output);
    process_test::faults = {};
    ASSERT_FALSE(before);
    EXPECT_GE(input.outputFD(), 0);
    EXPECT_GE(output.inputFD(), 0);
    process_test::faults.after_spawn = true;
    auto after = Process::exec(&input,
        {PROCESS_TEST_HELPER, "idle"}, &output);
    process_test::faults = {};
    ASSERT_FALSE(after);
    int raw_status;
    EXPECT_EQ(waitpid(-1, &raw_status, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
    // Also exercise rollback of a parked managed pump.
    std::string capture;
    process_test::faults.before_spawn = true;
    auto managed_before = Process::exec("input",
        {PROCESS_TEST_HELPER, "echo"}, &capture);
    process_test::faults = {};
    EXPECT_FALSE(managed_before);
    process_test::faults.after_spawn = true;
    auto managed_after = Process::exec("input",
        {PROCESS_TEST_HELPER, "echo"}, &capture);
    process_test::faults = {};
    EXPECT_FALSE(managed_after);
    EXPECT_EQ(waitpid(-1, &raw_status, WNOHANG), -1);
    EXPECT_EQ(errno, ECHILD);
}

TEST(Pipe, InjectedInterruptionsAndErrorsRetainProgress)
{
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    process_test::faults.write_interruptions = 3;
    auto written = pipe.writeUntil("abcdefgh", TestClock::now() + 1s);
    process_test::faults = {};
    ASSERT_TRUE(written);
    EXPECT_EQ(written->bytes_written, 8u);
    process_test::faults.read_interruptions = 3;
    auto read = pipe.readChunk(8, TestClock::now() + 1s);
    process_test::faults = {};
    ASSERT_TRUE(read);
    EXPECT_EQ(read->data, "abcdefgh");
    process_test::faults.write_calls_before_error = 1;
    auto failed = pipe.writeUntil("abcdefgh", TestClock::now() + 1s);
    process_test::faults = {};
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.error().as<ProcessError>()->code, EPIPE);
    EXPECT_EQ(failed.error().as<ProcessError>()->bytes_transferred, 4u);
    ASSIGN_OR_FAIL(auto prefix, receive(pipe, 4));
    EXPECT_EQ(prefix, "abcd");
    process_test::faults.read_interruptions = 100;
    auto timed = pipe.readChunk(8, TestClock::now());
    process_test::faults = {};
    ASSERT_TRUE(timed);
    EXPECT_EQ(timed->state, PipeState::DEADLINE_EXPIRED);
}

TEST(Exec, InterruptedStatusRetainsOwnership)
{
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "idle"}, nullptr));
    process_test::faults.wait_interruptions = 3;
    auto observed = proc.status();
    process_test::faults = {};
    ASSERT_TRUE(observed);
    EXPECT_FALSE(*observed);
    process_test::faults.wait_interruptions = 100;
    observed = proc.status();
    process_test::faults = {};
    ASSERT_FALSE(observed);
    EXPECT_EQ(observed.error().as<ProcessError>()->code, EINTR);
    process_test::faults.wait_interruptions = 100;
    auto interrupted_wait = proc.waitFor(0ms);
    process_test::faults = {};
    ASSERT_TRUE(interrupted_wait);
    EXPECT_EQ(interrupted_wait->state, ProcessWaitState::DEADLINE_EXPIRED);
    ASSIGN_OR_FAIL(auto done, proc.shutdown(0ms, TestClock::now() + 2s));
    EXPECT_EQ(done.state, ProcessWaitState::COMPLETE);
}

TEST(Exec, ExternalReapingInvalidatesOwnership)
{
    EXPECT_EXIT({
        auto input = Pipe::create();
        auto output = Pipe::create();
        if(!input || !output)
        {
            _exit(1);
        }
        auto proc = Process::exec(&*input,
            {PROCESS_TEST_HELPER, "identity"}, &*output);
        if(!proc)
        {
            _exit(2);
        }
        auto bytes = receive(*output, sizeof(pid_t));
        if(!bytes)
        {
            _exit(3);
        }
        pid_t pid;
        std::memcpy(&pid, bytes->data(), sizeof(pid));
        if(!input->closeInput() || waitpid(pid, nullptr, 0) != pid)
        {
            _exit(4);
        }
        auto observed = proc->status();
        if(observed || observed.error().as<ProcessError>()->code != ECHILD)
        {
            _exit(5);
        }
        auto again = proc->status();
        if(again || again.error().as<ProcessError>()->code != ECHILD)
        {
            _exit(6);
        }
        *proc = Process{};
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(Pipe, MoveClosesDestinationAndInvalidatesSource)
{
    ASSIGN_OR_FAIL(auto source, Pipe::create());
    ASSIGN_OR_FAIL(auto destination, Pipe::create());
    int old_input = destination.inputFD();
    int old_output = destination.outputFD();
    destination = std::move(source);
    EXPECT_EQ(source.inputFD(), -1);
    EXPECT_EQ(source.outputFD(), -1);
    EXPECT_EQ(fcntl(old_input, F_GETFD), -1);
    EXPECT_EQ(fcntl(old_output, F_GETFD), -1);
    auto& same = destination;
    destination = std::move(same);
    ASSERT_TRUE(destination.write("move"));
    ASSERT_TRUE(destination.closeInput());
    ASSIGN_OR_FAIL(auto data, destination.read());
    EXPECT_EQ(data, "move");
}


TEST(Exec, TimedCaptureAndShutdownPublishWithoutDuplication)
{
    std::string output;
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr,
        {PROCESS_TEST_HELPER, "capture"}, &output));
    auto watchdog = TestClock::now() + 3s;
    while(!output.ends_with("ready") && TestClock::now() < watchdog)
    {
        ASSIGN_OR_FAIL(auto timed, proc.waitFor(20ms));
        EXPECT_EQ(timed.state, ProcessWaitState::DEADLINE_EXPIRED);
        EXPECT_FALSE(timed.exit);
    }
    ASSERT_EQ(output, std::string(262144, 'x') + "ready");
    ASSIGN_OR_FAIL(auto stopped,
        proc.shutdown(100ms, TestClock::now() + 2s));
    EXPECT_EQ(stopped.state, ProcessWaitState::COMPLETE);
    EXPECT_EQ(stopped.exit->signal, SIGTERM);
    ASSIGN_OR_FAIL(auto done, proc.waitFor(1s));
    EXPECT_TRUE(done.output_complete);
    EXPECT_EQ(output, std::string(262144, 'x') + "ready");
}

TEST(Exec, ManagedInputFailureLeavesLifecycleQueryable)
{
    std::string output;
    std::string input(1024 * 1024, 'i');
    ASSIGN_OR_FAIL(auto proc, Process::exec(input,
        {PROCESS_TEST_HELPER, "close_stdin"}, &output));
    auto failed = proc.waitFor(3s);
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.error().as<ProcessError>()->code, EPIPE);
    auto observed = proc.status();
    ASSERT_TRUE(observed);
    EXPECT_FALSE(*observed);
    ASSERT_TRUE(proc.terminate(true));
    // Pump failure stays diagnostic, but wait still observes/reaps first.
    auto watchdog = TestClock::now() + 2s;
    do
    {
        failed = proc.waitFor(10ms);
        observed = proc.status();
        ASSERT_TRUE(observed);
        if(!*observed)
        {
            std::this_thread::sleep_for(1ms);
        }
    } while(!*observed && TestClock::now() < watchdog);
    ASSERT_TRUE(*observed);
    EXPECT_EQ((*observed)->signal, SIGKILL);
}

TEST(Pipe, IdleDeadlinePollsWithoutSpinningAndZeroWriteFails)
{
    ASSIGN_OR_FAIL(auto pipe, Pipe::create());
    process_test::faults = {};
    auto idle = pipe.readChunk(64, TestClock::now() + 30ms);
    int polls = process_test::faults.poll_calls;
    process_test::faults = {};
    ASSERT_TRUE(idle);
    EXPECT_EQ(idle->state, PipeState::DEADLINE_EXPIRED);
    EXPECT_GE(polls, 1);
    EXPECT_LT(polls, 10);
    process_test::faults.zero_write = true;
    auto failed = pipe.write("zero");
    process_test::faults = {};
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.error().as<ProcessError>()->code, EIO);
    EXPECT_EQ(failed.error().as<ProcessError>()->bytes_transferred, 0u);
}

TEST(Exec, CleanupAndFailedLaunchDoNotLeakDescriptors)
{
    size_t before = countDescriptors();
    for(int i = 0; i < 10; ++i)
    {
        std::string output;
        auto failed = Process::exec("input", {"no_such_libmw_program"},
                                    &output);
        EXPECT_FALSE(failed);
        ASSIGN_OR_FAIL(auto proc, Process::exec("input",
            {PROCESS_TEST_HELPER, "idle"}, &output));
    }
    EXPECT_EQ(countDescriptors(), before);
}


TEST(Exec, StalledChildConfirmsExactTimedWritePrefix)
{
    ASSIGN_OR_FAIL(auto input, Pipe::create());
    ASSIGN_OR_FAIL(auto output, Pipe::create());
    ASSIGN_OR_FAIL(auto control, Pipe::create());
    // Deliberate application-owned inheritance of a separate control FD.
    // All original libmw pipe endpoints remain close-on-exec.
    int control_fd = fcntl(control.outputFD(), F_DUPFD, 3);
    ASSERT_GE(control_fd, 3);
    std::string argument = std::to_string(control_fd);
    std::array<std::string_view, 3> args{
        PROCESS_TEST_HELPER, "gated_drain", argument};
    auto launched = Process::execArgs(&input, args, &output);
    ::close(control_fd);
    ASSERT_TRUE(launched);
    auto proc = std::move(*launched);
    ASSIGN_OR_FAIL(auto ready, receive(output, 5));
    EXPECT_EQ(ready, "ready");
    std::string bytes(1024 * 1024, 'p');
    ASSIGN_OR_FAIL(auto sent,
        input.writeUntil(bytes, TestClock::now() + 30ms));
    EXPECT_EQ(sent.state, PipeState::DEADLINE_EXPIRED);
    EXPECT_GT(sent.bytes_written, 0u);
    EXPECT_LT(sent.bytes_written, bytes.size());
    ASSERT_TRUE(input.closeInput());
    ASSERT_TRUE(control.write("g"));
    std::string expected = std::to_string(sent.bytes_written);
    ASSIGN_OR_FAIL(auto reported, receive(output, expected.size()));
    EXPECT_EQ(reported, expected);
    ASSIGN_OR_FAIL(auto done, proc.waitFor(2s));
    EXPECT_EQ(done.exit->exit_code, 0);
}

} // namespace mw
