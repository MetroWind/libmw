# Reliable subprocess lifecycle and streaming pipes

## Status and purpose

This is the proposed implementation design for
[todo-process.md](../todo-process.md).
It defines the APIs, ownership rules, algorithms, compatibility changes,
and tests needed to use libmw for Agent Smith's MCP stdio transport.
It does not implement the changes.

The primary use case is a long-lived child with a pipe connected to stdin
and another connected to stdout. The parent writes protocol frames, reads
chunks before EOF, and eventually closes stdin or terminates the child.
The child must remain manageable after an I/O timeout or wait timeout.

The implementation remains in `includes/mw/exec.hpp` and `src/exec.cpp`.
It uses C++23 and `mw::E<T>` for operational failures. Protocol framing,
JSON, request identifiers, and MCP cancellation remain in Agent Smith.

The first backend targets Linux with glibc 2.24 or newer. This is an
explicit backend constraint, not a claim of identical behavior on all
POSIX systems. Other backends must meet the same public contracts before
being enabled. In particular, generic POSIX spawn semantics can report a
child-side launch failure as exit status 127; that is insufficient for
our requirement to distinguish launch failure during `exec()`.

## Current behavior and defects

`Process::exec()` currently forks, configures descriptors in the child,
builds an argv vector there, and calls `execvp()`. It writes string input
synchronously in the parent before returning. Captured output is drained
only by `wait()`. These two operations can deadlock: the parent fills
stdin while the child fills stdout, and neither side drains the other.

The PID is assigned to `Process` only after fallible parent-side work.
An early return can therefore abandon a live child. Fork failure is not
checked. Child-side error macros can return into the caller's program,
instead of reporting failure and exiting the child.

`wait()` reads captured output to EOF before reaping. Launch failures can
return after reaping without clearing ownership. Destruction sends
`SIGKILL` without calling `waitpid()`. Move assignment swaps ownership
with the source rather than disposing of the destination's resources.

`Pipe::read()` waits for EOF. `write()` retries short writes, but does not
handle interruption, zero progress, deadlines, or SIGPIPE suppression.
Close failures leave the numeric descriptor stored in the object.

One requirement needs a factual correction: `Pipe::create()` already sets
`FD_CLOEXEC`. However, it uses `pipe()` followed by `fcntl()`, leaving a
window in which another thread can spawn a child that inherits the pipe.
The new implementation must create descriptors with close-on-exec set
atomically. See [O_CLOEXEC](https://man7.org/linux/man-pages/man2/open.2.html)
and [pipe2](https://man7.org/linux/man-pages/man2/pipe.2.html).

## Decisions

| Concern | Decision |
| --- | --- |
| Spawning | Linux/glibc `posix_spawnp`, no user C++ child code |
| Arguments | Length-aware core API plus existing C-string adapter |
| Process ownership | Exactly one owner; cache status after reaping |
| Lifecycle concurrency | Caller serializes calls on one `Process` |
| Pipe concurrency | One reader and one writer may operate concurrently |
| Close and move | Caller excludes operations on the affected endpoint |
| Deadlines | Absolute `steady_clock` deadlines, preserved across retries |
| Streaming | Chunk reads and writes with explicit progress |
| String convenience modes | An owned I/O pump prevents duplex deadlock |
| Cleanup | Kill direct child, reap it, cancel and join managed I/O |
| Descendants | Direct child only; process groups are deferred |
| Async integration | Native descriptors plus bounded calls; no new runtime |

Streaming callers using `Pipe*` do not get an internal I/O thread.
A thread is created only when string input or string output requires
library-managed I/O. This cost is restricted to the convenience path.

## Public data types

Add these declarations to `exec.hpp`, with the normal namespace wrapper
and required includes. Comments form part of the public contract.

```cpp
/// A monotonic absolute time limit for an operation.
using ProcessDeadline = std::chrono::steady_clock::time_point;

/// The reason an I/O operation stopped.
enum class PipeState
{
    COMPLETE,
    EOF_REACHED,
    WOULD_BLOCK,
    DEADLINE_EXPIRED,
};

/// Bytes received by one chunk read and its completion state.
struct PipeReadResult
{
    /// COMPLETE means data; EOF and timeout states have empty data.
    PipeState state;
    /// An arbitrary byte sequence, including embedded NUL bytes.
    std::string data;
};

/// The prefix of a write accepted before completion or timeout.
struct PipeWriteResult
{
    /// COMPLETE or DEADLINE_EXPIRED; no EOF state for writes.
    PipeState state;
    /// Number of bytes accepted by the kernel during this call.
    size_t bytes_written;
};

/// An operating-system failure, including progress before failure.
struct ProcessError
{
    /// A diagnostic containing the operation and relevant context.
    std::string msg;
    /// Saved errno or the error number returned by a POSIX function.
    int code;
    /// Bytes transferred in this call before an I/O error.
    size_t bytes_transferred = 0;
};

/// How a reaped child terminated.
enum class ProcessExitKind
{
    EXITED,
    SIGNALED,
};

/// The immutable result of reaping a child.
struct ProcessExit
{
    /// Selects which numeric status below is meaningful.
    ProcessExitKind kind;
    /// Valid only when kind is EXITED, including nonzero exit codes.
    int exit_code = 0;
    /// Valid only when kind is SIGNALED.
    int signal = 0;
    /// Whether the platform's wait status indicates a core dump.
    bool core_dumped = false;
};

/// Whether the requested wait condition was reached in time.
enum class ProcessWaitState
{
    COMPLETE,
    DEADLINE_EXPIRED,
};

/// A wait or shutdown result that preserves lifecycle and I/O state.
struct ProcessWaitResult
{
    /// Whether the method's documented completion condition was met.
    ProcessWaitState state;
    /// Present as soon as the direct child has been reaped.
    std::optional<ProcessExit> exit;
    /// True when managed capture reached EOF, or no capture was requested.
    bool output_complete = false;
};
```

`ProcessError` fits the existing type-erased `mw::Error`: callers can use
`error.as<ProcessError>()` without changing `error.hpp`. Save errno before
formatting messages or doing cleanup. Use error number zero for validation
failures that have no OS error number. Do not treat a nonzero child exit
code as an OS failure.

For failed reads, one chunk read never reports an error after delivering
bytes: a positive read returns immediately. For writes, an unexpected
`ProcessError` always carries the number of bytes already written in that
call. A timeout is a successful result with partial progress, not an
unexpected error. Kernel acceptance does not imply that the child parsed
or acted on the bytes.

## Pipe API and behavior

Keep `create()`, close methods, duplication methods, descriptor accessors,
and the existing `read()` and `write()` signatures. Add:

```cpp
/// Read at most max_bytes immediately; return WOULD_BLOCK if idle.
E<PipeReadResult> tryRead(size_t max_bytes = 65536) const;

/// Wait for one chunk, EOF, or the absolute deadline.
E<PipeReadResult> readChunk(
    size_t max_bytes, ProcessDeadline deadline) const;

/// Write the supplied bytes until complete, failed, or timed out.
E<PipeWriteResult> writeUntil(
    std::string_view data, ProcessDeadline deadline) const;
```

`max_bytes == 0` is a validation error, rather than an ambiguous empty
successful read. A chunk boundary has no protocol meaning. The client
must assemble messages across chunks and split multiple frames in one
chunk. An empty write succeeds with zero progress even at an expired
deadline, provided the endpoint is valid.

`read()` remains read-until-EOF and can block indefinitely. Implement it
using the same read engine with an unlimited deadline. `write()` similarly
uses `writeUntil()` with an unlimited deadline and discards progress on
success. Its failure still contains typed progress in `ProcessError`.
Use an internal optional deadline rather than subtracting or converting
`time_point::max()` to an overflowing poll timeout.

`Pipe::create()` uses `pipe2(O_CLOEXEC)` and initially creates blocking
endpoints. On first library I/O, set `O_NONBLOCK` on the affected endpoint
using `F_GETFL` and `F_SETFL`, preserving other flags. Read and write ends
have separate open file descriptions, so making the parent read end
nonblocking does not make the child's stdout nonblocking.

This conversion is permanent and also affects duplicates of that same
endpoint. Document it on descriptor accessors and duplication methods.
A descriptor handed to an external runtime must be configured before
concurrent use; that runtime must not change its flags during library I/O.
Serialize the first-time setup for each endpoint, or perform it before
starting concurrent operations. Do not write mutable shared bookkeeping
from `const` methods without synchronization.

A pipe endpoint selected for a child's stdin or stdout must be blocking.
Reject an already nonblocking selected endpoint during spawn preparation;
do not clear the flag, because that would alter a live parent operation
through the shared open file description. The ordinary parent-input /
child-stdin and parent-output / child-stdout arrangement uses opposite
endpoints and therefore remains valid. This restriction matters when a
caller reads a pipe itself and later tries to give that read end to a
child. Document the error and advise using a fresh pipe.

### Chunk-read algorithm

1. Validate the endpoint and requested buffer size.
2. Establish nonblocking mode and allocate the result buffer.
3. Attempt one read before checking the deadline, so already available
   data or EOF wins over a zero-duration wait.
4. A positive result returns `COMPLETE` with exactly those bytes.
5. Zero returns `EOF_REACHED`.
6. Retry `EINTR`, checking the deadline between attempts.
7. `EAGAIN` / `EWOULDBLOCK` means idle. `tryRead()` returns `WOULD_BLOCK`.
8. Otherwise wait with `poll()` for readable/error/hangup events, using
   the remaining monotonic deadline. Then retry the read.
9. Any other syscall error returns a typed error.

Hangup is a readiness indication, not permission to discard unread data.
Read buffered bytes before reporting EOF. Poll readiness is not a promise
that a later operation cannot block; nonblocking mode is essential.
See [poll](https://man7.org/linux/man-pages/man2/poll.2.html).

For finite deadlines, round positive remaining milliseconds upward and
clamp to `INT_MAX`. Recalculate after interruptions and spurious readiness.
Expiry returns promptly subject to scheduling and syscall overhead; it is
not a hard real-time guarantee.

### Write algorithm

1. Validate the endpoint and establish nonblocking mode.
2. Enter the per-thread SIGPIPE guard described below.
3. Attempt a write of the remaining suffix, using a bounded syscall size.
4. Add positive progress to the count. Never replay that prefix.
5. Check the deadline between attempts, even when progress is continuous.
6. Retry `EINTR`; on `EAGAIN`, poll for writable/error/hangup events.
7. An unexpected zero-byte write with nonempty input is an error, not a
   reason to spin indefinitely.
8. On another error, save errno and return typed partial progress.
9. On completion or deadline expiry, return the count and state.
10. Restore the signal mask on every return path.

An expired deadline permits one immediate nonblocking attempt, but never a
readiness wait. This makes zero-duration calls useful while placing a
fixed bound on immediate work. Chunk size limits and deadline checks
prevent continuous traffic from postponing timeout checks indefinitely.
See [write](https://man7.org/linux/man-pages/man2/write.2.html).

### SIGPIPE guard

Use `pthread_sigmask`, not process-wide signal disposition changes.

1. Save the calling thread's signal mask and block SIGPIPE.
2. Read the pending signal set before attempting writes.
3. If SIGPIPE was already pending, never consume it.
4. If a write returns `EPIPE` and SIGPIPE was not previously pending,
   use zero-timeout `sigtimedwait()` to consume the generated SIGPIPE.
   Retry interruption; `EAGAIN` is acceptable when no signal was generated
   because the application ignores SIGPIPE.
5. Restore the saved mask before returning.

Only attempt consumption after `EPIPE`, not after arbitrary failure or
success. The guard must also cover writes in the managed I/O pump.
Its cleanup uses allocation-free syscalls. Establishment failure prevents
writing and returns an error with zero progress. Preserve the primary
write error if cleanup also fails, adding cleanup context where possible.

POSIX standard signals do not carry a reliably separable queue of causes.
The contract preserves signals pending before the operation. It cannot
promise to distinguish a concurrently injected, unrelated SIGPIPE from a
write-generated signal; document this limitation rather than claiming
perfect isolation from arbitrary external signal injection.
See [pthread_sigmask](https://man7.org/linux/man-pages/man3/pthread_sigmask.3.html)
and [sigtimedwait](https://man7.org/linux/man-pages/man2/sigtimedwait.2.html).

### Descriptor lifetime and closing

Before calling `close()`, exchange the stored endpoint with `-1`.
On the Linux backend, do not retry a failed `close()`, including `EINTR`:
the descriptor number may already have been released and reused.
Explicit close returns diagnostic errors; destructors discard them.
See [close](https://man7.org/linux/man-pages/man2/close.2.html).

Closing an already closed endpoint succeeds. A read and a write on the
same `Pipe` may run concurrently after endpoint setup. There must be only
one reader per read endpoint and one writer per write endpoint. Closing
an endpoint requires its corresponding operation to have returned.
Moving or destroying a `Pipe` requires all its operations to have returned.
Raw descriptor borrowers and duplicates follow these same rules.

No internal mutex is held across an unlimited operation. Applications
coordinate shutdown through bounded operations and then close endpoints.
This avoids accessing a reused descriptor without promising unsupported
concurrent close cancellation.

Move construction transfers both descriptors and invalidates the source.
Move assignment first closes destination endpoints, then transfers source
endpoints; self-assignment succeeds without doing anything. Both moves
and the destructor are explicitly `noexcept` and use raw cleanup helpers.

## Process API

Retain the current `Input` and `Output` variants and C-string range entry
point. Add a separately named core entry point to avoid initializer-list
and template overload ambiguity:

```cpp
/// Launch directly from length-aware arguments; no shell evaluation.
static E<Process> execArgs(
    Input input, std::span<const std::string_view> args, Output output);

/// Query/reap the direct child without waiting for exit or output EOF.
E<std::optional<ProcessExit>> status();

/// Wait for child exit and completion of managed I/O until a deadline.
E<ProcessWaitResult> waitUntil(ProcessDeadline deadline);

/// Wait using one relative budget converted to an absolute deadline.
E<ProcessWaitResult> waitFor(std::chrono::milliseconds timeout);

/// Send SIGTERM or SIGKILL to an owned direct child without waiting.
E<void> terminate(bool force = false);

/// Send SIGTERM, escalate after grace, and wait only until deadline.
E<ProcessWaitResult> shutdown(
    std::chrono::milliseconds grace, ProcessDeadline deadline);
```

Use `Process()` as a documented empty handle, not a “do not use” object.
Operations needing a launched process return a validation error on an
empty or moved-from handle. Destruction is harmless. Internal cleanup is
idempotent even on empty handles.

`status()` returns an empty optional for a running child and a cached
`ProcessExit` for a reaped child. It does not wait for capture EOF or
report managed-I/O errors. This makes lifecycle inspection independent of
stream completion. Operational wait errors remain unexpected results.

`waitUntil()` completes only when the direct child has been reaped and
managed I/O has finished. A timeout includes any cached exit status and
capture completion flag. Thus a reaped child with a descendant still
holding stdout open can return `DEADLINE_EXPIRED` with `exit` present.
Partial capture is published before return and remains resumable.

`waitFor()` rejects negative durations, computes the deadline once, and
uses checked/saturating addition. Zero means immediate observation.
Repeated completed waits return the same result. A timeout does not reset
buffers, forget the child, or change its exit status.

The existing `E<int> wait()` uses unlimited `waitUntil()`. It returns the
exit code for normal termination and a typed diagnostic for signal
termination, preserving the old shape. New callers use structured status.
A legitimate exit code 127 is never interpreted as a launch failure.

`terminate(false)` requests SIGTERM; `terminate(true)` requests SIGKILL.
Neither closes externally supplied pipes. Calls after a cached exit are
successful no-ops. Empty handles produce validation errors. `shutdown()`
completion means the direct child was reaped, not that capture reached
EOF; its result explicitly exposes `output_complete`.

## Ownership and lifecycle state machine

Use a `std::unique_ptr<Impl>` in `Process`. Moving this pointer keeps the
pump's internal state at a stable address and needs no shared ownership.

`Impl` contains the following logical state:

- `pid_t pid`: strictly positive while owning a child, zero otherwise.
- `optional<ProcessExit> exit`: present only after successful reaping.
- `optional<ProcessError> ownership_error`: terminal error after ECHILD.
- Managed I/O descriptors, copied input, input offset, output buffer,
  pump thread, wake descriptor, mutex, stop-input/cancel flags, completion
  flag, and I/O error.
- The caller's output string pointer, used only by lifecycle calls.

| State | Representation | Permitted transition |
| --- | --- | --- |
| Empty | No implementation | Successful spawn to Owned |
| Owned | `pid > 0`, no cached exit | Reaped or Ownership lost |
| Reaped | `pid == 0`, cached exit | Retained until destruction/move |
| Ownership lost | `pid == 0`, cached ownership error | Retained error |

The managed I/O state is independent: active, completed, failed, or
cancelled. EOF need not coincide with exit, and exit need not imply EOF.

### Reaping algorithm

1. If an exit or ownership error is cached, return it without a syscall.
2. Call `waitpid(pid, &status, WNOHANG)` for exactly the owned PID.
3. On zero, retain ownership and report running.
4. On the owned PID, set `pid = 0` immediately, before allocating an error
   message, publishing output, or decoding termination.
5. Decode `WIFEXITED`, `WIFSIGNALED`, and the platform core-dump flag into
   a cached `ProcessExit`. Do not request stopped/continued notifications.
6. On `EINTR`, retry; bounded callers check their deadlines between retries.
   For `status()`, cap immediate EINTR retries at eight attempts and return
   an EINTR diagnostic if interrupted continuously; no ownership changes.
7. On `ECHILD`, clear `pid` immediately and cache ownership loss.
8. On another error, retain ownership and return a diagnostic.

Never use `wait()`, `waitpid(0, ...)`, or `waitpid(-1, ...)`.
The wait API and its ECHILD behavior are described in
[waitpid](https://man7.org/linux/man-pages/man2/waitpid.2.html).

Only libmw may reap a child it owns. The application must not install
SIGCHLD auto-reaping behavior or run a competing broad reaper. ECHILD is
handled defensively, but external reaping concurrent with `kill(pid, ...)`
can permit PID reuse before the signal. Without a stable kernel handle,
no PID-based design can guarantee safety under that contract violation.
Do not claim otherwise. A future pidfd backend could strengthen this.

### Timed waiting

Do not race a blocking wait thread against destruction. The lifecycle
owner loops over targeted nonblocking reaping and pump completion checks.
Sleep on the pump condition variable, or a timed sleep when there is no
pump, for at most 10 ms or the remaining budget, whichever is smaller.
Pump completion wakes the condition variable; child exit is detected by
the next targeted query. This bounded polling trades up to 10 ms of exit
notification latency for a simple backend with no global SIGCHLD handler.

Check the deadline after each iteration and EINTR. Already cached complete
results win over deadline expiry. A failed pump is reported through
`mw::E<>`; the child remains owned if not yet reaped. Reaping runs before
reporting a pump failure when a child exit is observable.

## Safe spawn transaction

Use `posix_spawnp()` on the selected backend. All argv construction,
allocation, descriptor preparation, and spawn-action construction happens
in the parent. There is no libmw-defined fork-child C++ execution.

The Linux/glibc spawn implementation communicates child setup/exec errors
back to the parent and reaps failed children. Verify that assumption in
backend tests rather than inferring it from generic POSIX behavior.
See [posix_spawn](https://man7.org/linux/man-pages/man3/posix_spawn.3.html)
and glibc's
[Linux implementation](https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/spawni.c).
A backend that can only report status 127 must use a separate safe launch
handshake or remain unsupported. Checking executable existence beforehand
is insufficient because files and permissions can change before exec.

### Preparation

1. Validate nonempty argv and a nonempty executable name. Reject embedded
   NUL bytes in every length-aware argument; permit empty non-first args.
2. Copy arguments into owned strings and construct a terminating-null
   pointer vector. The old adapter validates non-null C-string pointers
   and copies them before spawning. It cannot detect bytes beyond a C
   string terminator; document that limitation.
3. Reject null `Pipe*` or null output-string pointers in active variants,
   closed selected endpoints, incompatible endpoint routing, and
   nonblocking child endpoints.
4. Allocate `Impl`, copy string input, create all managed pipes and pump
   wake resources, and build spawn actions before creating the child.
5. If managed I/O is needed, start its thread in a parked state before
   spawning. Convert thread-creation failure to an error. Failed spawn
   releases the parked thread and joins it without starting I/O.
6. Configure only the parent's managed input write end and captured-output
   read end nonblocking. Child-facing ends remain blocking.

The parent environment, PATH, and exec-standard signal dispositions and
calling-thread mask are inherited. libmw does not globally alter signals
or silently unblock application-blocked signals in the child. Applications
that block or ignore SIGTERM must expect forced escalation. Spawn must not
run inside a temporary library SIGPIPE guard.

Concurrent mutation of the process environment by the application is outside
the supported contract.
Arguments are passed directly. No shell metacharacter interpretation or
fallback execution through `/bin/sh` is added. Scripts need an executable
interpreter directive. Test executable-format failures explicitly.

### Standard descriptor collisions

Every child stream source is first duplicated in the parent to a temporary
close-on-exec descriptor numbered at least 3, using `F_DUPFD_CLOEXEC`.
This avoids sources equal to stdin/stdout/stderr and avoids cycles where
one `dup2` overwrites a source needed by another action. See
[F_DUPFD_CLOEXEC](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html).

Build all duplication actions from those temporaries to standard targets
before close actions. Close original pipe endpoints in the child except
numeric slots now occupied by configured standard targets; close all
source temporaries after duplication. Child descriptors unrelated to
this launch and created by libmw are already close-on-exec.
Inherited stderr remains as the caller supplied it, including a closed
stderr. Do not open replacement standard descriptors as a side effect.
A generic close-all action is unnecessary and could change unrelated
caller-managed inheritance.

### Commit and rollback

1. Call `posix_spawnp()` and use its returned error number, not errno.
2. Failure leaves caller-owned pipe ends open and no owned child. Dispose
   of temporaries and managed resources and stop the parked pump.
3. On success, assign the positive PID to `Impl` immediately. Nothing may
   fail before this ownership assignment.
4. Close the parent's unused child ends, including the selected ends of
   externally supplied pipes, preserving the existing routing convention.
5. Release the pump start gate and return the owned `Process`.
6. If any post-spawn operation fails, use the now-owned process to kill
   and reap the child, cancel/join the pump, and return the original error.
   Supplied pipe ends already closed during commit remain closed; document
   this limited mutation on post-spawn failure.

Use small RAII helpers for spawn actions, attributes, and temporary FDs.
No destructor formats errors or allocates. Allocation and thread exceptions
are caught only at public preparation boundaries and converted when
possible. As elsewhere in libmw, complete recovery from allocator failure
is not guaranteed because constructing `mw::Error` itself allocates.

`exec()` guarantees launch diagnosis, not a deadline for executable
startup or protocol readiness. Spawn syscalls and executable loading can
be delayed by the OS. Protocol handshakes use the bounded pipe APIs.

## Managed string I/O pump

A single pump thread handles both copied string input and captured output
when either convenience mode is selected. It owns only managed endpoints;
it never reads or writes externally supplied `Pipe*` streams and never
signals or reaps the child.

The thread polls managed stdin for write readiness, managed stdout for
read readiness, and a Linux `eventfd(EFD_CLOEXEC | EFD_NONBLOCK)` for
cancellation. A single lifecycle owner writes the eventfd after setting a
command flag under the mutex; a saturated counter already means it is
readable. The
pump drains it, reads the flags, and either cancels all I/O or closes only
managed stdin. An input-stop request still permits output draining.
A future non-Linux backend can use a close-on-exec wake pipe instead.
See [eventfd](https://man7.org/linux/man-pages/man2/eventfd.2.html).

After the parked thread is released:

1. Close managed stdin immediately if the copied input is empty.
2. Poll all active descriptors together. Exclude a completed input from
   future poll sets and close its write end to deliver EOF.
3. On writable stdin, transfer a bounded chunk with the SIGPIPE guard and
   advance the offset. On readable stdout, read a bounded chunk.
4. Queue owned output chunks under the pump mutex. Do not touch the
   caller's string from the pump thread.
5. Service both directions per iteration; cap work per direction so
   continuous output cannot starve input or cancellation checks.
6. On EOF, close managed stdout and mark output complete.
7. Once both managed directions finish, mark the pump done and notify
   lifecycle waiters. It may finish before the child exits.
8. On error, save a typed error, close managed endpoints, mark done, and
   notify waiters. The process remains independently owned.
9. On cancellation, close endpoints and exit without waiting for EOF.

Catch allocation and other standard-library failures at the thread entry
boundary so no exception escapes the pump. Keep a preallocated fallback
failure flag for cases where constructing a detailed error fails. Public
lifecycle calls translate that flag to an error when allocation permits.
The pump never calls caller callbacks or blocks on a full output queue.

The output string supplied to `exec()` must outlive the `Process` and all
lifecycle calls. Clear it during successful launch commit. Publish buffered
output on `waitUntil()`, `shutdown()`, and legacy `wait()` returns, including
timeout/error returns. Track a publication offset so only the new suffix
is appended. The caller must not modify or concurrently access that string
while a lifecycle call publishes output.

Do not hold the pump mutex while performing output-string allocations.
Use a chunk queue that can transfer ownership without allocation under
the mutex, then append chunks outside it. Track publication per chunk;
remove a chunk only after its append succeeds. Keep unpublished chunks
owned if publication fails, without appending earlier chunks twice.
Deadline guarantees cover I/O/readiness waiting; allocation, copying, and
scheduling still add work
proportional to newly captured data. A caller needing tight bounded work
must use streaming pipes rather than unbounded string capture.

String capture preserves its existing unlimited-memory behavior. For a
long-lived MCP server, use streaming and apply application frame/buffer
limits. Adding a configurable capture limit is useful future work, but is
not required to replace the transport wrappers.

An external-output pipe can still deadlock if its caller never drains it.
The library cannot consume caller-owned protocol output automatically.
Document that pipeline consumers must run/drain concurrently with
producers; waiting on a producer before launching its consumer is invalid
for arbitrarily large output.

## Termination, shutdown, destruction, and moves

### Explicit termination

Before signaling, perform a targeted status query. If already reaped,
return success. Otherwise signal only the strictly positive owned PID.
On `ESRCH`, query again: the child may have exited and need reaping. Retain
ownership if it cannot yet be resolved; other signal failures return an
error. Never signal zero, minus one, or a cached reaped PID.

### Graceful then forced shutdown

`shutdown(grace, deadline)` rejects negative grace, computes
`grace_deadline = min(now + grace, deadline)` with checked addition, and:

1. Queries status and returns immediately if already reaped.
2. Stops further managed input and requests its write-end closure through
   the pump, waking it. External stdin is closed explicitly by the caller.
3. Sends SIGTERM to the owned child.
4. Waits for direct-child exit until the grace deadline while the pump
   continues draining managed output.
5. If still owned, sends SIGKILL once and waits for direct-child exit until
   the overall deadline.
6. Returns `COMPLETE` after reaping even if capture EOF has not arrived,
   or `DEADLINE_EXPIRED` while ownership remains.
7. Publishes output currently buffered without waiting for a descendant
   to close inherited stdout.

A zero grace period sends SIGTERM and immediately escalates if needed.
If the overall deadline has already expired, permit immediate observation
and signal requests but no waiting. Forced termination may remain pending
at deadline; later wait/shutdown or destruction still owns cleanup.
Repeated shutdowns may signal a still-owned child again but never a reaped
one. The cached exit status is immutable.

For an EOF-first policy, an MCP caller closes its input pipe, waits with a
chosen EOF grace budget, and calls `shutdown()` if the child remains alive.
This keeps the EOF phase explicit rather than silently consuming part of
the SIGTERM grace period.

### Destructor policy

The destructor is explicitly `noexcept` and performs allocation-free
cleanup. It first cancels managed I/O, then sends SIGKILL to an owned direct
child, calls targeted blocking `waitpid()` with EINTR retry, clears
ownership on successful reaping or ECHILD, joins the pump, and closes
remaining managed resources. It never waits for voluntary exit or stdout
EOF and never dereferences the caller's capture pointer.

This policy prevents ordinary zombie leaks without a global background
reaper. It cannot guarantee an exact wall-clock bound: a killed child in
uninterruptible kernel work may not become reapable promptly. An
application requiring a bounded shutdown call must use `shutdown()`;
final destruction retains the necessary reaping obligation. Errors that
cannot be returned by a destructor are discarded, not converted to
exceptions or callbacks.

Unexpected persistent wait/signal errors are exceptional OS failures;
the implementation must not busy-spin on them or pretend that cleanup
succeeded. Report them during explicit shutdown whenever possible. Tests
must prove the normal and ECHILD cleanup paths; they cannot establish
cleanup guarantees against arbitrary kernel failure.

Move construction transfers the implementation pointer. Move assignment
first applies destructor cleanup to the active destination, then transfers
ownership. Both are `noexcept`; assignment can incur the same kernel-bound
cleanup delay as destruction. A moved-from process is empty. Self-move is
harmless. These semantics replace the current swap-style assignment.

### Descendant boundary

The first implementation manages only the direct child. It does not kill
helpers or detached descendants and does not promise process-tree cleanup.
A descendant can hold stdout open after the direct child exits. Timed waits
expose that distinction; shutdown and destruction do not wait for that EOF.

The downstream completion criterion applies to direct stdio servers.
If Agent Smith requires terminating subprocess trees, a separate
process-group option and group-lifetime design must be implemented before
calling that broader case complete. Sending a negative cached PID is not a safe
shortcut after the group leader has been reaped. Process groups also do
not contain descendants that deliberately escape them.

## Concurrency contract and MCP usage

Lifecycle methods, moves, and destruction of one `Process` are serialized
by its caller. Different processes can be managed concurrently. Managed
I/O uses its own mutex and stop/wake protocol; it does not change this
public lifecycle rule.

For streaming, one thread may read child stdout while another writes its
stdin. They may also operate concurrently with process lifecycle calls,
because `Process` no longer retains or mutates external `Pipe*` objects
after successful launch. Endpoint closure still requires the corresponding
I/O operation to have completed.

A transport can use the following sequence:

1. Create separate input and output pipes.
2. Launch using `execArgs(&input, args, &output)`.
3. Write each frame using `writeUntil()` with a request budget. On timeout
   or error, inspect progress; do not replay an already delivered prefix.
4. Read using bounded `readChunk()` calls and assemble frames externally.
5. Stop new requests and let bounded I/O calls finish before closing ends.
6. Close stdin, then give the server a short EOF-based exit opportunity.
7. Use `shutdown()` for SIGTERM/SIGKILL escalation if still running.
8. Close stdout after its outstanding read returns, then destroy handles.

An external event loop may watch borrowed native descriptors while
preserving the documented lifetime and flag rules. No application-owned
spawn, waitpid, signal, or SIGPIPE wrapper is needed. Bounded calls can
also run on workers. Short polling is supported, but large numbers of
idle servers should use descriptor readiness integration rather than
continually scheduling workers for idle reads.

## Compatibility and source changes

| Existing behavior | New behavior |
| --- | --- |
| C-string argv range | Preserved as adapter; copied in parent |
| `exec("text", ..., &output)` | Preserved; string input copied and pumped |
| `exec()` writes input before returning | Input delivery continues after return |
| Invalid executable discovered by `wait()` | `exec()` fails immediately |
| `wait()` returns `E<int>` | Preserved; structured methods added |
| Wait exactly once | Repeated waits return cached results |
| Pipe EOF read | Preserved as unlimited convenience method |
| Pipe writes may kill application | SIGPIPE isolated per thread |
| Move assignment swaps destination into source | Destination cleaned; source empty |
| Default construction discouraged | Empty state explicitly supported |

The changed string-input delivery timing is necessary to prevent
deadlock during launch. A successful launch does not imply that input was
fully sent.
`wait()` reports managed input failure; streaming callers get exact
per-operation write progress. Existing output remains populated by
`wait()`, with partial output additionally available after timed waits.

Replace the invalid-command test that expects successful `exec()` and a
failed `wait()` with a failed-launch assertion. Keep existing pipeline,
container-argv, and large-output tests. Add public intention comments to
all currently uncommented interfaces while updating this header.

## Files and build integration

- `includes/mw/exec.hpp`: public results/errors, adapters, methods, contracts,
  and `unique_ptr<Impl>` declaration. Move spawning logic out of templates.
- `src/exec.cpp`: descriptor helpers, pipe engines, SIGPIPE guard, Linux
  spawn backend, lifecycle state machine, and managed I/O pump.
- `src/exec_test.cpp`: API-level behavior and lifecycle tests.
- `src/process_test_helper.cpp`: standalone deterministic child helper.
- `CMakeLists.txt`: helper executable when tests are enabled, helper path
  supplied to tests, and `Threads::Threads` linkage for library and tests.
- `README.adoc`: streaming example and concise lifetime/deadline guidance.
- `todo-process.md`: update the stale limitation and track completion when
  implementation is verified, rather than checking items off during design.

Define out-of-line `Process` construction/destruction/move operations where
`Impl` is complete. Use `find_package(Threads REQUIRED)` and express the
thread dependency on the static library so downstream CMake users receive
it. Keep Linux feature definitions private to the implementation where
possible. Avoid new general-purpose error or coroutine infrastructure.

## Test design

Use a dedicated child helper instead of shell commands for new edge cases.
Select helper behavior through argv. The helper supports echo-until-EOF,
idle, large duplex transfer, ignored SIGTERM, immediate exit, signal exit,
close-stdin, and a descendant retaining stdout. Readiness handshakes tell
the parent when a behavior is active; arbitrary sleeps do not establish
correctness. All tests have an outer watchdog to prevent CI hangs.

| Test group | Required observations |
| --- | --- |
| Streaming | Multiple replies arrive before EOF; binary bytes survive |
| Read deadlines | Idle expiry; later data/EOF succeeds; no busy spin |
| Write deadlines | Full pipe gives timeout and accurate prefix count |
| Broken input | Test process survives EPIPE; partial count is retained |
| Lifecycle | Nonzero and signal exits are structured and cached |
| Launch | Missing executable, ENOEXEC, permission, empty/null/NUL argv |
| Ownership | Destroy/move over live child reaps exactly its own PID |
| Isolation | Concurrent children cannot retain unrelated pipe ends |
| Interruption | EINTR retries preserve deadlines and progress |
| Managed I/O | Large input and output transfer without launch deadlock |
| Shutdown | EOF exit; SIGTERM exit; ignored SIGTERM escalates to SIGKILL |
| Descendants | Child exit and capture timeout remain distinguishable |
| Descriptor collisions | Spawn with 0/1/2 closed or reused works correctly |
| Concurrency | Many independent launches/I/O/cleanup cycles under threads |

### Assertions that require special care

For partial writes, the helper eventually drains stdin and reports the
exact bytes received through a separate control channel. Compare them
with the reported prefix, rather than assuming a fixed pipe capacity.
No test replays the original entire request after partial delivery.

For SIGPIPE, run cases with default, ignored, and custom dispositions;
with SIGPIPE blocked and unblocked; and with SIGPIPE already pending.
Compare masks and dispositions before/after. Execute default-disposition
cases in an isolated test subprocess so a regression is reported cleanly.

For unrelated children, the test harness owns an additional child and
verifies it can still reap that child itself. For libmw-owned children,
use test-only inspection of PID or helper reporting to check that another
targeted wait yields ECHILD after libmw reaps them. Do not expose private
PIDs merely for production transport code.

For descriptor collisions and injected setup failure, isolate changes in
a test subprocess so standard descriptors in the test runner stay intact.
Introduce narrow private syscall seams where real fault induction would
otherwise require races or resource exhaustion. Verify pre-spawn failure
leaves supplied pipes usable and post-spawn failure kills/reaps its child.

For external reaping, deliberately reap one libmw child in an isolated,
serialized test, then verify ECHILD clears ownership and later destruction
does not signal. This exercises defensive handling without endorsing a
competing reaper as a supported production arrangement.

For EINTR, deliver a harmless signal with a non-restarting handler to the
thread blocked in readiness waiting. Check interruption deterministically
through test instrumentation, and restore the handler. If a nonblocking
syscall's EINTR is difficult to induce, inject it through the private seam.

For timing, use generous scheduler tolerance and compare against a
watchdog substantially longer than the requested deadline. Check CPU or
poll-iteration counts to detect busy loops instead of requiring precise
wall-clock values. Run ASan/UBSan and TSan in separate builds; sanitizers
cannot all be enabled together.

## Implementation order and completion gates

1. Introduce raw noexcept descriptor cleanup and conventional moves.
   Add atomic close-on-exec creation and descriptor-collision tests.
2. Move spawning into the Linux backend, add length-aware argv, and make
   launch errors synchronous. Test rollback before/after spawn.
3. Add the lifecycle state machine, structured status, repeated waits,
   signal methods, destructor reaping, and move-over-active behavior.
4. Add nonblocking chunk/read/write engines, typed progress, monotonic
   deadlines, and per-thread SIGPIPE suppression.
5. Add the gated managed pump and cancellation channel. Prove large duplex
   string transfer and destructor cancellation without EOF.
6. Add timed wait and shutdown integration, including capture timeout after
   child exit and continued ownership after forced-shutdown timeout.
7. Update compatibility tests and README; run stress and sanitizer builds.
8. Integrate Agent Smith against the new public APIs and verify its stdio
   transport contains no private POSIX process or SIGPIPE wrapper.

Build with `cmake --build <build_dir> -j24`. Tests are optional through
`LIBMW_BUILD_TESTS`; keep this option and existing component build settings.
TSan needs a separate sanitizer configuration rather than the current
hardcoded ASan/UBSan flags. Check the test helper is built before test
execution and use its absolute build path.

The work is complete when every acceptance scenario in `todo-process.md`
is either verified or explicitly narrowed by the documented direct-child
and concurrency contracts, and the downstream direct-server transport
works through public libmw APIs. Design approval alone does not establish
that implementation or downstream integration has passed.
