#include <array>
#include <initializer_list>
#include <string>

#include <gtest/gtest.h>

#include "exec.hpp"
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
    ASSIGN_OR_FAIL(auto proc,
                   Process::exec(&input, {"fjdkal",}, &output_pipe));
    EXPECT_FALSE(isExpected(proc.wait()));
}

TEST(Exec, CanUseContainerAsArgs)
{
    std::array<const char*, 2> args = {"true", "1"};
    ASSIGN_OR_FAIL(auto proc, Process::exec(nullptr, args, nullptr));
    EXPECT_TRUE(isExpected(proc.wait()));
}

} // namespace mw
