# Add coroutine-friendly async HTTP client

## Context

`libmw` currently provides a synchronous HTTP client in
`includes/mw/http_client.hpp` and `url/src/http_client.cpp`. The public
client type is `mw::HTTPSession`, and each request eventually calls
`curl_easy_perform()`. That means the calling thread is blocked until the
request completes, fails, times out, or is aborted by a streaming callback.

The current synchronous implementation has useful behavior that should be
preserved:

- `HTTPRequest` stores the URL, request body, and headers.
- `HTTPResponse` stores the status, body bytes, and response headers.
- Errors are returned through `mw::E<T>`, not exceptions.
- `get()` and `post()` buffer the whole response body.
- `getStream()` and `postStream()` deliver body chunks through
  `ChunkCallback`.
- Session settings include transfer timeout, connection timeout, max response
  size, redirect behavior, redirect cap, protocol restrictions, Unix socket
  path, and address filtering.
- Address filtering uses `CURLOPT_OPENSOCKETFUNCTION`, so the filter sees the
  actual resolved address that curl is about to connect to.

The requested change is to add an asynchronous, C++23 coroutine-friendly HTTP
client. The implementation should use libcurl's multi interface rather than a
thread-per-request wrapper around the existing blocking client.

Useful references:

- [libcurl multi interface overview](https://curl.se/libcurl/c/libcurl-multi.html)
- [`curl_multi_poll`](https://curl.se/libcurl/c/curl_multi_poll.html)
- [`curl_multi_wakeup`](https://curl.se/libcurl/c/curl_multi_wakeup.html)
- [`curl_multi_info_read`](https://curl.se/libcurl/c/curl_multi_info_read.html)
- [`curl_multi_add_handle`](https://curl.se/libcurl/c/curl_multi_add_handle.html)
- [`curl_multi_remove_handle`](https://curl.se/libcurl/c/curl_multi_remove_handle.html)
- [`CURLOPT_PRIVATE`](https://curl.se/libcurl/c/CURLOPT_PRIVATE.html)
- [`CURLOPT_OPENSOCKETFUNCTION`](https://curl.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html)
- [C++ coroutines](https://en.cppreference.com/w/cpp/language/coroutines)
- [`std::coroutine_handle`](https://en.cppreference.com/w/cpp/coroutine/coroutine_handle)

## Goal

Add a new `mw::HTTPSessionAsync` class that supports coroutine-style HTTP
requests:

```cpp
mw::HTTPSessionAsync http;
mw::E<mw::HTTPResponse> res =
    co_await http.get(mw::HTTPRequest("https://example.com"));
```

The async client should allow many concurrent transfers to be in flight while
using one internal curl multi driver thread. A caller waiting on one request
should not block the caller's thread.

The async client should be self-contained. A user should not need to provide an
event loop, an executor, Boost.Asio, libuv, or another scheduler.

## Non-goals

Do not change `HTTPSession` into an async type. The synchronous class is useful
and should remain source-compatible.

Do not make `HTTPSessionAsync` inherit from `HTTPSessionInterface`.
`HTTPSessionInterface` returns `E<const HTTPResponse*>`, which depends on
session-owned response storage. Async requests need per-request response
storage, so the async API should return `E<HTTPResponse>` by value.

Do not introduce exceptions for normal request failures. Keep using `mw::E<T>`.

Do not design a general-purpose coroutine runtime for all of `libmw`. This
design only needs the scheduling machinery required to start an HTTP request,
suspend the awaiting coroutine, complete the request on the curl driver, and
resume the coroutine.

Do not initially implement the more complex `curl_multi_socket_action()` API.
That API is useful when integrating with an external event system such as
epoll, kqueue, libevent, or GLib. This design intentionally uses
`curl_multi_poll()` first because the async client owns its own driver thread.
The socket-action API can be added later if `libmw` gains an external event
loop integration.

## Public API

Add the public declarations to `includes/mw/http_client.hpp` or a new
`includes/mw/http_client_async.hpp`. Prefer a new header if the coroutine task
type becomes non-trivial. If the new header is used, it should include the
existing HTTP request/response types from `http_client.hpp`.

Recommended public shape:

```cpp
namespace mw
{

template<class T>
class Task;

class HTTPSessionAsync
{
public:
    HTTPSessionAsync();
    explicit HTTPSessionAsync(std::string_view socket_path);
    ~HTTPSessionAsync();

    HTTPSessionAsync(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync& operator=(const HTTPSessionAsync&) = delete;
    HTTPSessionAsync(HTTPSessionAsync&&) = delete;
    HTTPSessionAsync& operator=(HTTPSessionAsync&&) = delete;

    /// Start an HTTP GET request and complete with a buffered response.
    Task<E<HTTPResponse>> get(HTTPRequest req);

    /// Start an HTTP POST request and complete with a buffered response.
    Task<E<HTTPResponse>> post(HTTPRequest req);

    /// Start an HTTP GET request and deliver body chunks as they arrive.
    Task<E<HTTPResponse>> getStream(HTTPRequest req, ChunkCallback on_chunk);

    /// Start an HTTP POST request and deliver body chunks as they arrive.
    Task<E<HTTPResponse>> postStream(HTTPRequest req, ChunkCallback on_chunk);

    /// Return the timeout for the full transfer. Zero means no timeout.
    std::chrono::duration<long> transferTimeout() const;

    /// Set the timeout for the full transfer. Zero means no timeout.
    E<void> transferTimeout(std::chrono::duration<long> t);

    /// Return the connection timeout.
    std::chrono::duration<long> connectionTimeout() const;

    /// Set the connection timeout.
    E<void> connectionTimeout(std::chrono::duration<long> t);

    /// Return the maximum accepted download size.
    long maxSize() const;

    /// Set the maximum accepted download size.
    E<void> maxSize(long s);

    /// Return the redirect cap.
    long maxRedirections() const;

    /// Set the redirect cap.
    E<void> maxRedirections(long n);

    /// Return whether redirects are followed.
    bool followRedirects() const;

    /// Set whether redirects are followed.
    void followRedirects(bool follow);

    /// Return the connect-time address filter.
    const AddressPredicate& addressFilter() const;

    /// Set the connect-time address filter.
    void addressFilter(AddressPredicate pred);

    /// Restrict protocols allowed for the initial request.
    E<void> allowedProtocols(std::string_view protocols);

    /// Restrict protocols allowed for redirects.
    E<void> allowedRedirectProtocols(std::string_view protocols);
};

} // namespace mw
```

Every public item needs an intention comment because the project style requires
comments for public interface items.

The async methods take `HTTPRequest` by value. This is deliberate. A request
may outlive the caller's stack frame after coroutine suspension, so the async
client must own its copy of the URL, payload, and headers.

The async methods return `E<HTTPResponse>` by value. This is also deliberate.
The synchronous API returns `const HTTPResponse*` because the response is stored
inside the session object. That model is not valid when multiple requests are
running at the same time. Each async request owns exactly one response object,
and that object is moved into the coroutine result.

## Task type

C++23 provides the coroutine language feature but not a standard `Task<T>` type.
`libmw` therefore needs a small task type.

The task type has two jobs:

1. Represent an asynchronous operation that can be `co_await`ed.
2. Hold the coroutine state for functions such as
   `HTTPSessionAsync::get()`.

The task does not need to be a full scheduler. It does not need timers,
thread-pool APIs, work stealing, sender/receiver support, or custom executors.
The curl driver thread is the only scheduler needed for HTTP completion.

Recommended initial semantics:

- `Task<T>` is move-only.
- `Task<T>` is lazy: the coroutine body starts when the task is awaited.
- `Task<T>` can be awaited exactly once.
- Destroying an un-awaited task destroys its coroutine frame.
- Destroying an awaited task before completion is not supported in the first
  implementation unless cancellation is implemented at the same time.

The simplest implementation can use a common coroutine promise pattern:

```cpp
template<class T>
class Task
{
public:
    struct promise_type;

    Task(Task&& other) noexcept;
    Task& operator=(Task&& other) noexcept;
    ~Task();

    auto operator co_await() &&;

private:
    explicit Task(std::coroutine_handle<promise_type> h);
    std::coroutine_handle<promise_type> handle = nullptr;
};
```

The promise stores:

- `std::optional<T> value`
- `std::optional<Error>` or another way to represent unexpected coroutine
  exceptions
- `std::coroutine_handle<> continuation`

Even though normal HTTP failures use `mw::E<T>`, coroutine body bugs can still
throw accidentally from allocation, `std::function`, `std::string`, or other
standard library operations. `promise_type::unhandled_exception()` should catch
that and convert it into `runtimeError("...")` when possible. If conversion is
too broad for the first version, terminate explicitly and document that the
task type is not exception-transparent. The rest of `libmw` favors explicit
errors, so converting to `runtimeError` is preferred.

Because all async HTTP methods return `Task<E<HTTPResponse>>`, the task's `T`
is already an expected-like result. Avoid nesting another `E<T>` around
coroutine infrastructure errors. If task infrastructure errors need to be
reported, store them as `T` by constructing an unexpected `mw::Error`.

## Internal architecture

`HTTPSessionAsync` owns an implementation object. Use the pimpl pattern so the
public header does not expose driver-thread details, mutexes, condition
variables, curl multi handles, or request-state containers.

Recommended private shape:

```cpp
class HTTPSessionAsync::Impl
{
public:
    Impl();
    explicit Impl(std::string_view socket_path);
    ~Impl();

    RequestAwaiter start(HTTPRequest req, HTTPMethod method,
                         ChunkCallback on_chunk);

private:
    CURLM* multi = nullptr;
    std::thread driver;
    std::mutex mutex;
    bool stopping = false;

    std::deque<std::unique_ptr<HTTPRequestState>> pending;
    std::unordered_map<CURL*, std::unique_ptr<HTTPRequestState>> active;

    HTTPSessionOptions options;

    void run();
    void addPendingRequests();
    void completeFinishedRequests();
    void completeRequest(HTTPRequestState& state, CURLcode code);
    void failAllPendingAndActive(std::string_view msg);
};
```

`HTTPSessionAsync` should store `std::unique_ptr<Impl> impl;`.

This follows the project preference for `unique_ptr` over `shared_ptr`.
Request state ownership is always singular:

- pending request state is owned by the `pending` queue;
- active request state is owned by the `active` map;
- completed state is moved into the awaiting coroutine result and then
  destroyed.

No request state should be shared by reference-counted ownership.

## Session options

Create a private reusable options struct:

```cpp
struct HTTPSessionOptions
{
    std::optional<std::string> socket;
    long transfer_timeout_s = 0;
    long connection_timeout_s = 60;
    long max_size = 2147483648;
    long max_redirections = 0;
    bool follow_redirects = true;
    AddressPredicate addr_filter;
    std::string allowed_protocols;
    std::string allowed_redir_protocols;
};
```

The synchronous `HTTPSession` already stores these fields directly. The async
client can initially duplicate them. A later refactor can move common setup
logic into shared helpers once the async implementation is stable.

Access to options must be synchronized because callers may set options while
the driver thread is running. The safest initial rule is:

- Lock `Impl::mutex` when reading or writing `options`.
- Copy `options` into each `HTTPRequestState` at request start.
- Never read session-level options from curl callbacks.

Copying options into request state gives each request a stable configuration.
For example, if a caller changes `followRedirects(false)` after request A
starts but before request B starts, request A keeps the old setting and request
B gets the new setting. This is predictable and avoids data races.

The address predicate is a `std::function`. Copying it into request state means
the predicate object remains alive for the duration of the transfer.

## Request state

Each in-flight request needs independent storage:

```cpp
enum class HTTPMethod
{
    GET,
    POST,
};

struct OpenSocketCtx
{
    const AddressPredicate* filter = nullptr;
    bool blocked = false;
};

struct StreamCtx
{
    ChunkCallback* cb = nullptr;
    bool aborted = false;
};

struct HTTPRequestState
{
    HTTPRequest req;
    HTTPMethod method = HTTPMethod::GET;
    HTTPSessionOptions options;

    CURL* easy = nullptr;
    curl_slist* headers = nullptr;

    HTTPResponse res;
    ChunkCallback on_chunk;
    StreamCtx stream_ctx;
    OpenSocketCtx socket_ctx;

    std::coroutine_handle<> continuation = nullptr;
    std::optional<E<HTTPResponse>> result;
};
```

`HTTPRequestState` owns the easy handle and the curl header list. Its destructor
must clean both:

```cpp
~HTTPRequestState()
{
    if(headers != nullptr)
    {
        curl_slist_free_all(headers);
    }
    if(easy != nullptr)
    {
        curl_easy_cleanup(easy);
    }
}
```

When a request is active inside the multi handle, the destructor must not run
until after `curl_multi_remove_handle()` has been called. Enforce this by making
the driver remove the handle before erasing the active map entry.

Use `CURLOPT_PRIVATE` to store the `HTTPRequestState*` on the easy handle. When
`curl_multi_info_read()` reports a completed easy handle, call
`curl_easy_getinfo(easy, CURLINFO_PRIVATE, &state_ptr)` to recover the state.
This is simpler and less error-prone than searching all active requests.

## Request setup

Factor easy-handle setup into one private function:

```cpp
E<void> configureEasy(HTTPRequestState& state);
```

The function should:

1. Create `state.easy` with `curl_easy_init()`.
2. Return `runtimeError(...)` if the handle cannot be created.
3. Configure `CURLOPT_PRIVATE` with `&state`.
4. Configure the URL with `state.req.url.c_str()`.
5. Build `state.headers` from `state.req.header`.
6. Configure `CURLOPT_HTTPHEADER` if headers exist.
7. Configure timeout, connection timeout, maximum size, redirect behavior,
   redirect cap, protocol restrictions, and Unix socket path from
   `state.options`.
8. Configure the header callback to write into `state.res`.
9. Configure either the buffered body callback or the streaming body callback.
10. Configure POST fields when `state.method == HTTPMethod::POST`.
11. Configure `CURLOPT_OPENSOCKETFUNCTION` and `CURLOPT_OPENSOCKETDATA` when
    `state.options.addr_filter` is non-empty.

The setup should use the existing synchronous callback logic as much as
possible:

- `writeResponse()` appends body bytes to `HTTPResponse::payload`.
- `writeHeaders()` parses status and headers into `HTTPResponse`.
- `writeChunk()` calls the user streaming callback and marks abort state.
- `openSocketCallback()` translates libcurl socket addresses into `SockAddr`
  and runs the address predicate.

These callbacks can be made free functions in an anonymous namespace or shared
private helpers. The current implementation has them as static private methods
of `HTTPSession`. If async needs them too, moving them to file-local helpers in
`http_client.cpp` is cleaner than making `HTTPSessionAsync` a friend.

## Coroutine awaiter

The async HTTP methods should construct an awaiter object tied to a request
state. The awaiter is responsible for registering the awaiting coroutine handle.

Conceptual shape:

```cpp
class RequestAwaiter
{
public:
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> h);
    E<HTTPResponse> await_resume();

private:
    HTTPSessionAsync::Impl* impl = nullptr;
    HTTPRequest req;
    HTTPMethod method = HTTPMethod::GET;
    ChunkCallback on_chunk;
    std::shared_ptr<RequestResultSlot> slot;
};
```

However, avoid `shared_ptr` unless it is strictly necessary. A better first
design is for `Task<E<HTTPResponse>> HTTPSessionAsync::get(...)` to be a
coroutine and `co_await` an internal awaiter whose lifetime is inside the
coroutine frame:

```cpp
Task<E<HTTPResponse>> HTTPSessionAsync::get(HTTPRequest req)
{
    co_return co_await impl->start(std::move(req), HTTPMethod::GET, {});
}
```

In this shape, `RequestAwaiter` can own a raw pointer to request state because
the awaiter object lives in the coroutine frame until `await_resume()` returns.
The driver completes the request by writing the result into that state and
resuming the stored continuation.

The implementation must be careful about ownership:

- Before suspension, the awaiter creates a `unique_ptr<HTTPRequestState>`.
- In `await_suspend()`, the awaiter stores the coroutine handle in the state
  and moves the state into `Impl::pending`.
- The driver moves the state from `pending` to `active`.
- On completion, the driver moves `state.result` into a result slot inside the
  awaiter or coroutine frame, removes the easy handle, and resumes the
  coroutine.
- `await_resume()` returns the result by value.

If moving the result back into the awaiter without shared ownership becomes too
awkward, introduce a tiny heap-allocated `RequestOperation` owned by the
awaiter and referenced by the driver. This is not the same as using shared
ownership. The coroutine frame owns the operation until completion; the driver
only has a non-owning pointer while the operation is active. The operation must
not be destroyed while active.

## Driver thread

The driver thread owns all calls that mutate the curl multi handle:

- `curl_multi_add_handle`
- `curl_multi_remove_handle`
- `curl_multi_perform`
- `curl_multi_poll`
- `curl_multi_info_read`
- `curl_multi_cleanup`

Keeping those calls on one thread avoids having to reason about libcurl multi
handle thread safety. Public methods may be called from other threads, but they
only enqueue work under a mutex and wake the driver.

Recommended loop:

```cpp
void HTTPSessionAsync::Impl::run()
{
    int running = 0;

    while(true)
    {
        addPendingRequests();

        CURLMcode code = curl_multi_perform(multi, &running);
        if(code != CURLM_OK)
        {
            failAllPendingAndActive(curl_multi_strerror(code));
        }

        completeFinishedRequests();

        {
            std::lock_guard lock(mutex);
            if(stopping && pending.empty() && active.empty())
            {
                break;
            }
        }

        int numfds = 0;
        code = curl_multi_poll(multi, nullptr, 0, 1000, &numfds);
        if(code != CURLM_OK)
        {
            failAllPendingAndActive(curl_multi_strerror(code));
        }
    }
}
```

The real implementation should avoid holding `mutex` while calling libcurl
callbacks or resuming coroutines. Libcurl callbacks can call user code through
`ChunkCallback` or `AddressPredicate`. Coroutine resumption can also run user
code immediately. Holding the mutex across user code can deadlock if user code
calls back into the session.

Use `curl_multi_wakeup(multi)` when public methods enqueue a new request or
when the destructor asks the driver to stop. `curl_multi_poll()` is designed to
be woken by `curl_multi_wakeup()`, which prevents the driver from sleeping until
the poll timeout expires.

The poll timeout should be a small bounded value such as 1000 ms. Libcurl may
shorten the wait internally when it has an earlier timeout. A long timeout is
acceptable only if every enqueue and shutdown path calls `curl_multi_wakeup()`.

## Starting a request

Starting a request has two phases because the public thread and the driver
thread have different responsibilities.

Public/coroutine thread:

1. The caller calls `http.get(req)`.
2. The returned `Task<E<HTTPResponse>>` is awaited.
3. The task coroutine reaches `impl->start(...)`.
4. The awaiter copies current session options under `mutex`.
5. The awaiter creates `HTTPRequestState`.
6. The awaiter stores the awaiting coroutine handle in the state.
7. The awaiter moves the state into `pending`.
8. The awaiter calls `curl_multi_wakeup(multi)`.
9. The awaiter returns control to the caller by suspending.

Driver thread:

1. `curl_multi_poll()` wakes.
2. The driver moves all pending states into a local vector while holding the
   mutex briefly.
3. The driver releases the mutex.
4. For each pending state, the driver configures the easy handle.
5. If setup fails, the driver stores an unexpected result and resumes the
   coroutine.
6. If setup succeeds, the driver calls `curl_multi_add_handle()`.
7. The driver stores the state in `active[easy]`.
8. The driver calls `curl_multi_perform()`.

Do not call `curl_multi_add_handle()` from the public/coroutine thread. Keeping
all multi-handle mutation in the driver thread is simpler and safer.

## Completing a request

After each `curl_multi_perform()` and after each `curl_multi_poll()` wakeup,
the driver should drain completion messages:

```cpp
void HTTPSessionAsync::Impl::completeFinishedRequests()
{
    int queued = 0;
    while(CURLMsg* msg = curl_multi_info_read(multi, &queued))
    {
        if(msg->msg != CURLMSG_DONE)
        {
            continue;
        }

        CURL* easy = msg->easy_handle;
        HTTPRequestState* state = nullptr;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &state);

        curl_multi_remove_handle(multi, easy);
        completeRequest(*state, msg->data.result);

        auto node = active.extract(easy);
        // The state is owned by node.mapped(). Destroy it after resume
        // decisions are complete.
    }
}
```

`completeRequest()` maps libcurl completion to `E<HTTPResponse>`:

- If the curl code is `CURLE_OK`, return a response.
- For buffered requests, move `state.res` into the successful result.
- For streaming requests, return a response with status and headers, but an
  empty payload, matching the synchronous streaming semantics.
- If the curl code is `CURLE_WRITE_ERROR` and `state.stream_ctx.aborted` is
  true, return `runtimeError(HTTP_ABORTED_BY_CALLER)`.
- If `state.socket_ctx.blocked` is true, return
  `policyError(HTTP_BLOCKED_BY_POLICY)`.
- Otherwise return `runtimeError(curl_easy_strerror(code))`.

After storing the result, resume the coroutine handle:

```cpp
std::coroutine_handle<> h = state.continuation;
state.continuation = nullptr;
h.resume();
```

Do not hold `mutex` while calling `h.resume()`.

## Streaming callbacks

The initial streaming async design should preserve the synchronous callback
contract as much as possible:

- `ChunkCallback` receives each body chunk.
- Returning `true` continues the transfer.
- Returning `false` aborts the transfer.
- Aborting returns `runtimeError(HTTP_ABORTED_BY_CALLER)`.
- The final `HTTPResponse` contains status and headers but no payload.

The important difference is thread affinity. In the async client,
`ChunkCallback` runs on the curl driver thread because libcurl invokes write
callbacks from the thread that calls `curl_multi_perform()`.

Document this clearly in the public comment:

```cpp
/// The callback runs on the HTTPSessionAsync driver thread.
```

This matters because callers must not do expensive work, blocking waits, or UI
updates directly inside the callback. If a caller needs callback execution on a
specific application thread, that should be a later executor/dispatcher
feature.

## Address filtering

Address filtering must keep the same security property as the synchronous
client: the predicate sees the exact address that curl is about to connect to.

The async client should reuse the existing `SockAddr`, `AddressPredicate`, and
open-socket callback approach. Each request state has its own `OpenSocketCtx`.
That context points to the request's copied `AddressPredicate`.

The callback must not capture references to session-level options. The session
options can change while a request is active, and the callback may run at any
time during the transfer. Always point at `state.options.addr_filter`.

When the predicate rejects a connection, set `state.socket_ctx.blocked = true`
and return `CURL_SOCKET_BAD`. Completion should then translate the failure to
`policyError(HTTP_BLOCKED_BY_POLICY)`.

## Cancellation

Cancellation is useful but should be implemented only after the basic async
request path works.

Initial cancellation policy:

- Destroying `HTTPSessionAsync` cancels all pending and active requests.
- Individual request cancellation is not part of the first public API.
- Destroying an awaited task before completion is undefined or prohibited by
  documentation in the first version.

Session destruction should:

1. Lock `mutex`.
2. Set `stopping = true`.
3. Mark all pending requests as cancelled.
4. Wake the driver with `curl_multi_wakeup()`.
5. Join the driver thread.
6. The driver removes all active easy handles, completes their awaiters with
   `runtimeError("transfer cancelled")`, and exits.

After the first implementation is stable, add a request cancellation handle:

```cpp
class HTTPRequestHandle
{
public:
    /// Request cancellation of the associated async HTTP operation.
    void cancel();
};
```

Or add cancellation through `Task<T>` destruction if the task type is designed
to support it safely. Do not add both until the ownership model is fully clear.

## Shutdown behavior

The destructor of `HTTPSessionAsync` must not return while the driver thread is
still running. The destructor should also not leave suspended coroutines that
will never resume.

Required behavior:

- Pending requests complete with a runtime cancellation error.
- Active requests are removed from the multi handle and complete with a runtime
  cancellation error.
- The driver joins before `curl_multi_cleanup()`.
- No coroutine is resumed while holding `mutex`.
- No easy handle is cleaned up while still inside the multi handle.

One subtle issue is resuming coroutines during destruction. A coroutine may run
user code that refers to the session being destroyed. This is dangerous.

Recommended rule:

- The user must ensure `HTTPSessionAsync` outlives all tasks started from it.
- The destructor is a final cleanup path, not a normal cancellation mechanism.

Even with that rule, the destructor should complete outstanding requests rather
than leaking suspended coroutines.

## Thread safety

Public methods should be thread-safe in the limited sense that multiple caller
threads may start requests or change options without data races.

Rules:

- Protect `pending`, `stopping`, and `options` with `mutex`.
- Do not protect `active` with `mutex` if only the driver thread accesses it.
- Do not call libcurl multi functions outside the driver thread.
- Do not hold `mutex` while invoking callbacks or resuming coroutines.
- Do not let callbacks access destroyed request state.

Changing options while requests are running affects only future requests
because each request copies the options at start.

## Error handling

Use existing error helpers:

- `runtimeError(...)` for curl failures, setup failures, cancellation, and
  internal driver failures.
- `policyError(HTTP_BLOCKED_BY_POLICY)` for address-filter rejections.
- `runtimeError(HTTP_ABORTED_BY_CALLER)` for streaming callback aborts.

Do not use HTTP status codes as transport errors. The existing synchronous
client treats an HTTP 404 or 500 as a successful transfer with
`HTTPResponse::status` set to that value. The async client should match this.

If `curl_multi_add_handle()` fails for a request, complete that request with
`runtimeError(curl_multi_strerror(code))`.

If `curl_multi_perform()` or `curl_multi_poll()` fails at the multi-handle
level, the state of all transfers may be unreliable. Complete every pending
and active request with a runtime error, clean up the multi handle, and stop the
driver. This is a severe internal failure.

## File layout

Recommended files:

- `includes/mw/task.hpp`
  - Defines `mw::Task<T>`.
- `includes/mw/http_client_async.hpp`
  - Declares `mw::HTTPSessionAsync`.
- `url/src/http_client_async.cpp`
  - Implements `HTTPSessionAsync`, request state, and driver logic.
- `url/src/http_client_common.cpp` or shared anonymous-namespace helpers
  - Optional later refactor for shared curl callbacks and setup helpers.
- `url/src/http_client_async_test.cpp`
  - Unit tests for async behavior.

If adding a new source file, update `url/CMakeLists.txt`:

- Add `src/http_client_async.cpp` to `SOURCE_FILES`.
- Add `../includes/mw/http_client_async.hpp` and `../includes/mw/task.hpp` to
  `HEADERS`.
- Add `src/http_client_async_test.cpp` to `TEST_FILES`.

## Implementation order

Implement in small steps.

1. Add `Task<T>` with a tiny test that awaits a coroutine returning an `int`.
   This proves the coroutine return type works before curl is involved.

2. Add `HTTPSessionAsync` skeleton with constructor, destructor, pimpl, driver
   thread startup, `stopping` flag, and clean shutdown. The driver can initially
   loop and wait without processing requests.

3. Add request state and a `get()` implementation for buffered responses.
   Configure easy handles with URL, body callback, header callback, and
   `CURLOPT_PRIVATE`.

4. Add completion handling with `curl_multi_info_read()`. Verify `get()` can
   fetch a local test server response.

5. Add `post()` with payload setup.

6. Add session options: timeouts, max size, redirects, protocol restrictions,
   Unix socket path, and address filter.

7. Add streaming variants.

8. Add shutdown cancellation for pending and active requests.

9. Refactor duplicated callback code between sync and async only after both
   implementations have passing tests. Avoid mixing a behavior change with a
   large refactor.

## Tests

Add tests beside the existing HTTP client tests.

### Task tests

`TaskReturnsValue`

- Define a coroutine returning `Task<int>`.
- `co_return 3`.
- Await it from a small test helper.
- Verify the result is `3`.

`TaskPropagatesExpected`

- Define a coroutine returning `Task<E<int>>`.
- `co_return std::unexpected(runtimeError("fail"))`.
- Verify the caller receives the unexpected error.

### Basic async HTTP tests

`HTTPSessionAsyncCanGet`

- Start a local `httplib` server.
- Return a known body and status.
- Await `HTTPSessionAsync::get()`.
- Verify status, body, and headers.

`HTTPSessionAsyncCanPost`

- Start a local server that checks the request body.
- Await `post()`.
- Verify the response.

`HTTPSessionAsyncConcurrentGets`

- Start a local server with two endpoints that each sleep briefly.
- Start two async GET requests before awaiting both results.
- Verify both complete correctly.
- The elapsed time should be closer to one sleep than two sleeps, with a loose
  threshold to avoid flaky timing.

### Option tests

`HTTPSessionAsyncConnectionTimeout`

- Configure a very short connection timeout against an unroutable or controlled
  endpoint if the existing test style already uses one.
- Verify a runtime error is returned.
- Avoid relying on external internet.

`HTTPSessionAsyncAddressFilterBlocksLoopback`

- Start a local loopback server.
- Install a predicate that rejects loopback.
- Await `get()`.
- Verify the result is unexpected and the error is `PolicyError` with
  `HTTP_BLOCKED_BY_POLICY`.

`HTTPSessionAsyncAllowedProtocols`

- Restrict protocols to a value that does not allow the test URL.
- Verify the request fails.

### Streaming tests

`HTTPSessionAsyncStreamDeliversChunks`

- Start a local server that emits chunks.
- Await `getStream()` with a callback that appends chunks to a local buffer
  protected by the test's coroutine flow.
- Verify chunk order.
- Verify final response status and headers exist while payload is empty.

`HTTPSessionAsyncStreamCallbackAbort`

- Callback returns false after the first chunk.
- Verify result is unexpected with `HTTP_ABORTED_BY_CALLER`.

### Shutdown tests

`HTTPSessionAsyncDestructorCancelsPendingRequest`

- Start a request to a server endpoint that blocks.
- Destroy the session.
- Verify the test does not hang.

This test must be written carefully because using a destroyed session from a
resumed coroutine is invalid. It may be better as an internal driver test than
a public API test.

## Documentation

Update `README.adoc` to mention that `mw::url` offers both:

- `HTTPSession` for synchronous HTTP requests.
- `HTTPSessionAsync` for coroutine-friendly async HTTP requests.

Document the important semantic differences:

- Async returns `E<HTTPResponse>` by value.
- Streaming callbacks run on the internal driver thread.
- The session must outlive tasks started from it.
- Options are copied at request start.

## Future work

Add an executor/dispatcher hook if users need coroutine continuation on a
specific thread:

```cpp
class Executor
{
public:
    /// Schedule a continuation for later execution.
    virtual void post(std::coroutine_handle<> h) = 0;
};
```

With that hook, the driver would complete the request, then pass the coroutine
handle to the executor instead of calling `resume()` directly. This is useful
for UI loops or applications that require request continuations to run on a
main thread.

Add `curl_multi_socket_action()` integration if `libmw` later grows an
event-loop abstraction. That would allow the caller's event loop to wait on
curl sockets directly instead of using the internal polling driver thread.

Add per-request cancellation once the initial ownership model is proven. The
right cancellation API should be chosen after real use shows whether callers
prefer explicit handles, task destruction, or cancellation tokens.

## Acceptance criteria

- `HTTPSessionAsync` can run multiple GET/POST requests concurrently through
  one curl multi driver thread.
- Public async methods are coroutine-friendly and return
  `Task<E<HTTPResponse>>`.
- Buffered requests return `HTTPResponse` by value.
- Streaming requests preserve the existing chunk callback and abort semantics.
- Address filtering still checks the actual resolved destination address for
  every connection, including redirects.
- Session options are copied into each request at start and do not race with
  active transfers.
- The driver thread shuts down cleanly.
- Tests cover basic GET, POST, concurrency, streaming, callback abort, address
  filter rejection, and at least one shutdown path.
