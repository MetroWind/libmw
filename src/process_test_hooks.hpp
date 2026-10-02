#pragma once

// Private seams compiled only into mw_test, never the library API.
namespace mw::process_test
{
struct Faults
{
    bool before_spawn = false;
    bool after_spawn = false;
    int read_interruptions = 0;
    int write_interruptions = 0;
    int wait_interruptions = 0;
    int write_calls_before_error = -1;
    bool zero_write = false;
    int poll_calls = 0;
};
extern thread_local Faults faults;
}
