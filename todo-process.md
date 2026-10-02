# Process and Pipe Requirements

## Goal

Make `mw::Process` and `mw::Pipe` suitable for long-lived, bidirectional
stdio subprocesses in a multithreaded application. Agent Smith's MCP
client should be able to use libmw instead of implementing its own
process spawning, termination, child reaping, and pipe I/O wrappers.

This document specifies requirements, not a final API design. Preserve
existing callers where practical; document any required API changes.

## Previous limitations (addressed by design 10)

- `Process::wait()` blocks until the child exits. There is no timed or
  nonblocking wait, or supported way to terminate a running process.
- The process destructor sends `SIGKILL` but does not reap the child.
- `wait()` can return an error after reaping without clearing process
  ownership, leaving later cleanup able to signal a stale PID.
- `Process::exec()` uses `fork()` and allocates in the child before
  `execvp()`. Its spawn path does not explicitly handle `fork()` failure.
- `Pipe::read()` reads until EOF, rather than returning an available
  chunk. It cannot receive messages from a server that keeps stdout open.
- `Pipe::write()` has no deadline, does not retry interrupted writes,
  and does not protect the application from `SIGPIPE`.
- Pipe descriptors previously used `pipe()` followed by `fcntl(FD_CLOEXEC)`,
  leaving a concurrent-spawn inheritance window. They now use atomic
  `pipe2(O_CLOEXEC)`.

## Process lifecycle

- [x] Provide a nonblocking child-status query and a deadline-bounded wait.
  Distinguish a still-running child or expired deadline from a wait error.
- [x] Preserve a running process after a timed wait expires: the caller
  must still be able to terminate it or wait again.
- [x] Provide explicit termination without exposing private process state
  or requiring callers to invoke raw POSIX APIs.
- [x] Support graceful termination followed by forced termination when a
  caller-selected grace period expires. Closing stdin to request an
  EOF-based exit must also be usable before termination.
- [x] Reap every owned child exactly once, including signal-terminated
  children, failed executable launches, and destructor cleanup.
- [x] Clear ownership as soon as a child is reaped, even when reporting
  abnormal termination as an error. Never signal a previously reaped PID.
- [x] Define repeated wait and shutdown behavior. Repeated cleanup must
  not kill unrelated processes or reap children belonging to another owner.
- [x] Make destruction noexcept and document its cleanup policy. It must
  not wait indefinitely for voluntary child exit or leak zombies. Explain
  OS-level limitations: even forced termination cannot guarantee an exact
  wall-clock bound for a child stuck in uninterruptible kernel work.
- [x] Define move construction and assignment ownership, including cleanup
  of an already-running destination and harmless moved-from destruction.
- [x] Distinguish normal exit status, termination signal, and launch/wait
  errors without losing useful diagnostic information.
- [x] Retry interrupted wait operations and handle an externally reaped
  child safely; do not use broad `wait()`/`waitpid(-1, ...)` calls.
- [x] Document supported concurrency. It is acceptable to require serialized
  lifecycle calls on one process, provided bounded operations allow callers
  to coordinate shutdown without racing a blocking wait against destruction.

## Safe spawning and descriptor ownership

- [x] Make spawning safe in a multithreaded parent. Prefer `posix_spawn`
  where suitable, or restrict a fork child's work to async-signal-safe
  operations until exec. Do not run ordinary C++ allocation or cleanup there.
- [x] Return launch failures through `mw::E<>`, including empty commands,
  executable lookup errors, descriptor setup errors, and spawn failure.
  A failed launch must leave no child or descriptor leaks.
- [x] Report executable launch failure during `exec()`, rather than requiring
  an eventual blocking `wait()` to discover it.
- [x] Pass argv directly, without shell interpretation. Reject arguments
  containing embedded NUL bytes rather than silently truncating them.
- [x] Use close-on-exec descriptors by default, including internal error
  reporting pipes. Only explicitly configured child streams may survive exec.
- [x] Close unused pipe ends in parent and child. Launching a second process
  must not keep the first process's stdin or stdout alive.
- [x] Preserve configurable stdin/stdout routing and inherited stderr.
  Account for descriptor-number collisions with standard descriptors.

## Streaming pipe I/O

- [x] Add chunk-oriented reads that return without waiting for EOF.
  Distinguish received bytes, EOF, deadline expiry, and would-block status.
- [x] Support bounded readiness/read operations so an idle subprocess does
  not occupy a worker indefinitely. A native coroutine API is not required;
  short bounded operations must be usable by an external async runtime.
- [x] Support deadline-bounded writes and report how many bytes were written
  before failure or timeout. Callers need this information to avoid replaying
  a partially delivered request with side effects.
- [x] Retry `EINTR`, handle short reads/writes, and handle `EAGAIN` without
  busy-spinning or treating it as EOF. Zero-progress writes must not loop
  forever. Use a monotonic deadline across retries.
- [x] Writing after the peer exits must return an error, not terminate the
  application with `SIGPIPE`. Do not globally change signal handling or
  consume a signal that was already pending for unrelated work.
- [x] Define close-versus-I/O concurrency and descriptor lifetime explicitly
  so a reused descriptor cannot be accessed by an outstanding operation.
- [x] Keep existing read-until-EOF behavior available for simple callers.
  Document how it interacts with captured output and timed process waits;
  output collection must not defeat a requested wait deadline or deadlock
  when a child fills its stdout pipe.

Protocol framing, JSON parsing, request routing, and MCP cancellation
notifications remain application responsibilities, not libmw features.

## Acceptance tests

- [x] Exchange several newline-delimited messages with a child that keeps
  stdout open; verify a reply is readable before EOF.
- [x] An idle child allows read and wait deadlines to expire promptly,
  without busy-spinning; a later read or wait still succeeds.
- [x] Close stdin and reap an EOF-aware child normally.
- [x] Terminate and reap a child that ignores EOF and graceful termination.
- [x] Destroy an active process and verify that no zombie or pipe remains.
- [x] Exercise nonzero exit, signal exit, missing executable, invalid argv,
  and interrupted I/O/wait paths. Verify ownership is cleared after reaping.
- [x] Repeat wait/close/termination and move operations, including assignment
  over an active process; verify no double reap or stale-PID signaling.
- [x] Start multiple children and verify that one cannot keep another's
  pipe open through inherited descriptors. Verify unrelated children are
  never reaped by libmw.
- [x] Fill a child's stdin pipe while it stops reading; verify a write
  deadline expires with accurate partial-progress reporting.
- [x] Write after a child closes stdin; verify the test process survives and
  its existing signal mask and signal handling are preserved.
- [x] Capture output exceeding pipe capacity without deadlock, including
  during timed waits and shutdown.
- [x] Stress launch, I/O, termination, and cleanup in a multithreaded parent.
  Run relevant tests under ASan and TSan where supported.

## Downstream completion criterion

Agent Smith's MCP stdio transport can launch a server with `mw::Process`,
read streaming chunks and write frames with `mw::Pipe`, and shut down an
unresponsive server through supported libmw APIs. No application-owned
spawn, signal, waitpid, or SIGPIPE-management wrapper is necessary.


## Implementation verification

The Linux/glibc 2.24+ backend implements design 10 in `exec.hpp` and
`exec.cpp`. API tests cover streaming binary replies before EOF, resumable
read/wait deadlines, child-confirmed exact partial writes, SIGPIPE masks
and dispositions (including previously pending signals), synchronous
launch failures, EINTR and zero-progress injection, rollback before/after
spawn, cached normal/signal exit, ECHILD ownership loss, targeted reaping,
move/destructor cleanup, standard descriptor collisions, descriptor leak
checks, managed duplex transfers and partial capture publication,
descendant-held stdout, and concurrent independent process cycles.

Verification completed outside the sandbox:

- Full all-component build with `cmake --build build -j24` and CTest:
  106/106 tests passed with ASan, UBSan, and leak detection enabled.
- Separate core build with `LIBMW_TEST_SANITIZERS=thread`:
  44/44 tests passed under TSan.
- `git diff --check` passed.

Lifecycle calls on one handle must be serialized. One reader and one
writer per pipe are supported; close/move must exclude affected I/O.
Only the direct child is managed, and no competing reaper or SIGCHLD
execution policy that auto-reaps children is supported. Cleanup can still
be delayed by uninterruptible kernel work. These are the design's explicit
contract boundaries, rather than unverified process-tree guarantees.

- [ ] Agent Smith integration: update its stdio transport to the public
  libmw APIs and verify the direct-server transport end to end. The local
  transport remains separate work in progress; this library change does
  not mark that downstream criterion complete.
