#include <algorithm>
#include <charconv>
#include <coroutine>
#include <cstddef>
#include <cstring>
#include <deque>
#include <format>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "error.hpp"
#include "http_client_async.hpp"

namespace mw
{

namespace
{

enum class HTTPMethod
{
    GET,
    POST,
};

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

struct RequestOperation
{
    std::optional<E<HTTPResponse>> result;
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
    RequestOperation* operation = nullptr;

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
};

bool toSockAddr(const struct curl_sockaddr* address, SockAddr& out)
{
    const struct sockaddr* addr = &address->addr;
    if(addr->sa_family == AF_INET)
    {
        const struct sockaddr_in* in =
            reinterpret_cast<const struct sockaddr_in*>(addr);
        out.family = AddressFamily::IPV4;
        out.address.resize(4);
        std::memcpy(out.address.data(), &in->sin_addr.s_addr, 4);
        out.port = ntohs(in->sin_port);
        return true;
    }
    if(addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6* in6 =
            reinterpret_cast<const struct sockaddr_in6*>(addr);
        const std::uint8_t* bytes =
            reinterpret_cast<const std::uint8_t*>(&in6->sin6_addr);
        out.port = ntohs(in6->sin6_port);
        static constexpr std::uint8_t V4_MAPPED_PREFIX[12] =
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if(std::memcmp(bytes, V4_MAPPED_PREFIX, 12) == 0)
        {
            out.family = AddressFamily::IPV4;
            out.address.assign(bytes + 12, bytes + 16);
        }
        else
        {
            out.family = AddressFamily::IPV6;
            out.address.assign(bytes, bytes + 16);
        }
        return true;
    }
    return false;
}

curl_socket_t openSocketCallback(void* clientp, curlsocktype purpose,
                                 struct curl_sockaddr* address)
{
    OpenSocketCtx* ctx = static_cast<OpenSocketCtx*>(clientp);
    if(purpose == CURLSOCKTYPE_IPCXN && ctx != nullptr &&
       ctx->filter != nullptr && *ctx->filter)
    {
        SockAddr sa;
        if(toSockAddr(address, sa) && !(*ctx->filter)(sa))
        {
            ctx->blocked = true;
            return CURL_SOCKET_BAD;
        }
    }
    return ::socket(address->family, address->socktype, address->protocol);
}

curl_slist* headersFromReq(const HTTPRequest& req)
{
    curl_slist* headers = nullptr;
    for(const auto& [key, value]: req.header)
    {
        headers = curl_slist_append(
            headers, std::format("{}: {}", key, value).c_str());
    }
    return headers;
}

size_t writeResponse(char* ptr, size_t size, size_t nmemb, void* res_buffer)
{
    size_t real_size = size * nmemb;
    HTTPResponse* response = reinterpret_cast<HTTPResponse*>(res_buffer);
    size_t old_size = response->payload.size();
    response->payload.resize(old_size + real_size);
    std::memcpy(response->payload.data() + old_size, ptr, real_size);
    return real_size;
}

size_t writeChunk(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    size_t real_size = size * nmemb;
    StreamCtx* ctx = reinterpret_cast<StreamCtx*>(userdata);
    std::span<const std::byte> chunk(
        reinterpret_cast<const std::byte*>(ptr), real_size);
    bool keep_going = (*ctx->cb)(chunk);
    if(!keep_going)
    {
        ctx->aborted = true;
        return real_size == 0 ? 1 : real_size - 1;
    }
    return real_size;
}

size_t writeHeaders(char* buffer, [[maybe_unused]] size_t size, size_t nitems,
                    void* userdata)
{
    if(nitems == 0)
    {
        return 0;
    }

    std::string line(buffer, nitems);
    if(line.back() == '\n')
    {
        line.pop_back();
        if(!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
    }

    if(line.empty())
    {
        return nitems;
    }

    HTTPResponse* res = reinterpret_cast<HTTPResponse*>(userdata);
    if(line.starts_with("HTTP/"))
    {
        size_t first_space_index = line.find_first_of(' ');
        if(first_space_index == std::string::npos)
        {
            return 0;
        }
        size_t second_space_index =
            line.find_first_of(' ', first_space_index + 1);
        if(second_space_index == std::string::npos)
        {
            return 0;
        }
        std::from_chars(line.data() + first_space_index + 1,
                        line.data() + second_space_index, res->status);
        return nitems;
    }

    size_t colon_index = line.find_first_of(':');
    if(colon_index == std::string::npos)
    {
        return nitems;
    }

    std::string_view key(std::begin(line),
                         std::next(std::begin(line), colon_index));
    size_t i = colon_index + 1;
    while(i < line.size() && line[i] == ' ')
    {
        i++;
    }
    std::string_view value(std::next(std::begin(line), i), std::end(line));
    res->header.emplace(key, value);
    return nitems;
}

} // namespace

class RequestAwaiter
{
public:
    RequestAwaiter(HTTPSessionAsync::Impl* impl, HTTPRequest req,
                   HTTPMethod method, ChunkCallback on_chunk);

    bool await_ready() const noexcept
    {
        return false;
    }

    void await_suspend(std::coroutine_handle<> h);
    E<HTTPResponse> await_resume();

private:
    HTTPSessionAsync::Impl* impl = nullptr;
    HTTPRequest req;
    HTTPMethod method = HTTPMethod::GET;
    ChunkCallback on_chunk;
    RequestOperation operation;
};

class HTTPSessionAsync::Impl
{
public:
    Impl()
    {
        multi = curl_multi_init();
        driver = std::thread([this]() { run(); });
    }

    explicit Impl(std::string_view socket_path)
            : Impl()
    {
        std::lock_guard lock(mutex);
        options.socket = socket_path;
    }

    ~Impl()
    {
        {
            std::lock_guard lock(mutex);
            stopping = true;
        }
        if(multi != nullptr)
        {
            curl_multi_wakeup(multi);
        }
        if(driver.joinable())
        {
            driver.join();
        }
        if(multi != nullptr)
        {
            curl_multi_cleanup(multi);
        }
    }

    RequestAwaiter start(HTTPRequest req, HTTPMethod method,
                         ChunkCallback on_chunk)
    {
        return RequestAwaiter(this, std::move(req), method,
                              std::move(on_chunk));
    }

    HTTPSessionOptions copyOptions()
    {
        std::lock_guard lock(mutex);
        return options;
    }

    void enqueue(std::unique_ptr<HTTPRequestState> state)
    {
        bool stopped = false;
        {
            std::lock_guard lock(mutex);
            if(stopping)
            {
                stopped = true;
            }
            else
            {
                pending.push_back(std::move(state));
            }
        }

        if(stopped)
        {
            state->operation->result =
                std::unexpected(runtimeError("transfer cancelled"));
            state->continuation.resume();
            return;
        }
        curl_multi_wakeup(multi);
    }

    std::chrono::duration<long> transferTimeout() const
    {
        std::lock_guard lock(mutex);
        return std::chrono::duration<long>(options.transfer_timeout_s);
    }

    E<void> transferTimeout(std::chrono::duration<long> t)
    {
        std::lock_guard lock(mutex);
        options.transfer_timeout_s = t.count();
        return {};
    }

    std::chrono::duration<long> connectionTimeout() const
    {
        std::lock_guard lock(mutex);
        return std::chrono::duration<long>(options.connection_timeout_s);
    }

    E<void> connectionTimeout(std::chrono::duration<long> t)
    {
        std::lock_guard lock(mutex);
        options.connection_timeout_s = t.count();
        return {};
    }

    long maxSize() const
    {
        std::lock_guard lock(mutex);
        return options.max_size;
    }

    E<void> maxSize(long s)
    {
        std::lock_guard lock(mutex);
        options.max_size = s;
        return {};
    }

    long maxRedirections() const
    {
        std::lock_guard lock(mutex);
        return options.max_redirections;
    }

    E<void> maxRedirections(long n)
    {
        std::lock_guard lock(mutex);
        options.max_redirections = n;
        return {};
    }

    bool followRedirects() const
    {
        std::lock_guard lock(mutex);
        return options.follow_redirects;
    }

    void followRedirects(bool follow)
    {
        std::lock_guard lock(mutex);
        options.follow_redirects = follow;
    }

    const AddressPredicate& addressFilter() const
    {
        std::lock_guard lock(mutex);
        return options.addr_filter;
    }

    void addressFilter(AddressPredicate pred)
    {
        std::lock_guard lock(mutex);
        options.addr_filter = std::move(pred);
    }

    E<void> allowedProtocols(std::string_view protocols)
    {
        std::lock_guard lock(mutex);
        options.allowed_protocols = protocols;
        return {};
    }

    E<void> allowedRedirectProtocols(std::string_view protocols)
    {
        std::lock_guard lock(mutex);
        options.allowed_redir_protocols = protocols;
        return {};
    }

private:
    friend class RequestAwaiter;

    CURLM* multi = nullptr;
    std::thread driver;
    mutable std::mutex mutex;
    bool stopping = false;

    std::deque<std::unique_ptr<HTTPRequestState>> pending;
    std::unordered_map<CURL*, std::unique_ptr<HTTPRequestState>> active;
    HTTPSessionOptions options;

    void run()
    {
        int running = 0;

        while(true)
        {
            addPendingRequests();

            CURLMcode code = curl_multi_perform(multi, &running);
            if(code != CURLM_OK)
            {
                failAllPendingAndActive(curl_multi_strerror(code));
                break;
            }

            completeFinishedRequests();

            if(shouldStop())
            {
                cancelActiveRequests();
                break;
            }

            int numfds = 0;
            code = curl_multi_poll(multi, nullptr, 0, 1000, &numfds);
            if(code != CURLM_OK)
            {
                failAllPendingAndActive(curl_multi_strerror(code));
                break;
            }

            completeFinishedRequests();
        }
    }

    bool shouldStop()
    {
        std::lock_guard lock(mutex);
        return stopping;
    }

    void addPendingRequests()
    {
        std::deque<std::unique_ptr<HTTPRequestState>> ready;
        {
            std::lock_guard lock(mutex);
            ready.swap(pending);
        }

        for(auto& state: ready)
        {
            E<void> setup = configureEasy(*state);
            if(!setup.has_value())
            {
                completeWithError(*state, setup.error());
                continue;
            }

            CURLMcode code = curl_multi_add_handle(multi, state->easy);
            if(code != CURLM_OK)
            {
                completeWithError(*state, runtimeError(
                    curl_multi_strerror(code)));
                continue;
            }

            active.emplace(state->easy, std::move(state));
        }
    }

    E<void> configureEasy(HTTPRequestState& state)
    {
        state.easy = curl_easy_init();
        if(state.easy == nullptr)
        {
            return std::unexpected(runtimeError(
                "could not create curl easy handle"));
        }

        curl_easy_setopt(state.easy, CURLOPT_PRIVATE, &state);
        curl_easy_setopt(state.easy, CURLOPT_URL, state.req.url.c_str());

        state.headers = headersFromReq(state.req);
        if(state.headers != nullptr)
        {
            curl_easy_setopt(state.easy, CURLOPT_HTTPHEADER, state.headers);
        }

        if(state.options.socket.has_value())
        {
            curl_easy_setopt(state.easy, CURLOPT_UNIX_SOCKET_PATH,
                             state.options.socket->c_str());
        }
        curl_easy_setopt(state.easy, CURLOPT_TIMEOUT,
                         state.options.transfer_timeout_s);
        curl_easy_setopt(state.easy, CURLOPT_CONNECTTIMEOUT,
                         state.options.connection_timeout_s);
        curl_easy_setopt(state.easy, CURLOPT_MAXFILESIZE,
                         state.options.max_size);
        curl_easy_setopt(state.easy, CURLOPT_FOLLOWLOCATION,
                         state.options.follow_redirects ? 1L : 0L);
        curl_easy_setopt(state.easy, CURLOPT_MAXREDIRS,
                         state.options.max_redirections);

        if(!state.options.allowed_protocols.empty())
        {
            curl_easy_setopt(state.easy, CURLOPT_PROTOCOLS_STR,
                             state.options.allowed_protocols.c_str());
        }
        if(!state.options.allowed_redir_protocols.empty())
        {
            curl_easy_setopt(state.easy, CURLOPT_REDIR_PROTOCOLS_STR,
                             state.options.allowed_redir_protocols.c_str());
        }

        curl_easy_setopt(state.easy, CURLOPT_HEADERFUNCTION, writeHeaders);
        curl_easy_setopt(state.easy, CURLOPT_HEADERDATA, &state.res);

        if(state.on_chunk)
        {
            state.stream_ctx = StreamCtx{&state.on_chunk, false};
            curl_easy_setopt(state.easy, CURLOPT_WRITEFUNCTION, writeChunk);
            curl_easy_setopt(state.easy, CURLOPT_WRITEDATA,
                             &state.stream_ctx);
        }
        else
        {
            curl_easy_setopt(state.easy, CURLOPT_WRITEFUNCTION, writeResponse);
            curl_easy_setopt(state.easy, CURLOPT_WRITEDATA, &state.res);
        }

        if(state.method == HTTPMethod::POST)
        {
            curl_easy_setopt(state.easy, CURLOPT_POSTFIELDS,
                             state.req.request_data.data());
            curl_easy_setopt(state.easy, CURLOPT_POSTFIELDSIZE,
                             state.req.request_data.size());
        }

        if(state.options.addr_filter)
        {
            state.socket_ctx = OpenSocketCtx{
                &state.options.addr_filter, false};
            curl_easy_setopt(state.easy, CURLOPT_OPENSOCKETFUNCTION,
                             openSocketCallback);
            curl_easy_setopt(state.easy, CURLOPT_OPENSOCKETDATA,
                             &state.socket_ctx);
        }

        return {};
    }

    void completeFinishedRequests()
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
            active.erase(easy);
        }
    }

    void completeRequest(HTTPRequestState& state, CURLcode code)
    {
        if(code == CURLE_OK)
        {
            if(state.on_chunk)
            {
                HTTPResponse out;
                out.status = state.res.status;
                out.header = std::move(state.res.header);
                state.operation->result = std::move(out);
            }
            else
            {
                state.operation->result = std::move(state.res);
            }
        }
        else if(code == CURLE_WRITE_ERROR && state.stream_ctx.aborted)
        {
            state.operation->result =
                std::unexpected(runtimeError(HTTP_ABORTED_BY_CALLER));
        }
        else if(state.socket_ctx.blocked)
        {
            state.operation->result =
                std::unexpected(policyError(HTTP_BLOCKED_BY_POLICY));
        }
        else
        {
            state.operation->result =
                std::unexpected(runtimeError(curl_easy_strerror(code)));
        }

        auto continuation = state.continuation;
        state.continuation = nullptr;
        continuation.resume();
    }

    void completeWithError(HTTPRequestState& state, Error error)
    {
        state.operation->result = std::unexpected(std::move(error));
        auto continuation = state.continuation;
        state.continuation = nullptr;
        continuation.resume();
    }

    void failAllPendingAndActive(std::string_view msg)
    {
        std::deque<std::unique_ptr<HTTPRequestState>> pending_requests;
        {
            std::lock_guard lock(mutex);
            pending_requests.swap(pending);
            stopping = true;
        }

        for(auto& state: pending_requests)
        {
            completeWithError(*state, runtimeError(msg));
        }

        for(auto& [easy, state]: active)
        {
            curl_multi_remove_handle(multi, easy);
            completeWithError(*state, runtimeError(msg));
        }
        active.clear();
    }

    void cancelActiveRequests()
    {
        std::deque<std::unique_ptr<HTTPRequestState>> pending_requests;
        {
            std::lock_guard lock(mutex);
            pending_requests.swap(pending);
        }

        for(auto& state: pending_requests)
        {
            completeWithError(*state, runtimeError("transfer cancelled"));
        }

        for(auto& [easy, state]: active)
        {
            curl_multi_remove_handle(multi, easy);
            completeWithError(*state, runtimeError("transfer cancelled"));
        }
        active.clear();
    }
};

RequestAwaiter::RequestAwaiter(HTTPSessionAsync::Impl* impl, HTTPRequest req,
                               HTTPMethod method, ChunkCallback on_chunk)
        : impl(impl),
          req(std::move(req)),
          method(method),
          on_chunk(std::move(on_chunk))
{}

void RequestAwaiter::await_suspend(std::coroutine_handle<> h)
{
    auto state = std::make_unique<HTTPRequestState>();
    state->req = std::move(req);
    state->method = method;
    state->options = impl->copyOptions();
    state->on_chunk = std::move(on_chunk);
    state->continuation = h;
    state->operation = &operation;
    impl->enqueue(std::move(state));
}

E<HTTPResponse> RequestAwaiter::await_resume()
{
    if(!operation.result.has_value())
    {
        return std::unexpected(runtimeError(
            "async HTTP operation completed without a result"));
    }
    return std::move(*operation.result);
}

HTTPSessionAsync::HTTPSessionAsync()
        : impl(std::make_unique<Impl>())
{}

HTTPSessionAsync::HTTPSessionAsync(std::string_view socket_path)
        : impl(std::make_unique<Impl>(socket_path))
{}

HTTPSessionAsync::~HTTPSessionAsync() = default;

Task<E<HTTPResponse>> HTTPSessionAsync::get(HTTPRequest req)
{
    co_return co_await impl->start(std::move(req), HTTPMethod::GET, {});
}

Task<E<HTTPResponse>> HTTPSessionAsync::post(HTTPRequest req)
{
    co_return co_await impl->start(std::move(req), HTTPMethod::POST, {});
}

Task<E<HTTPResponse>> HTTPSessionAsync::getStream(HTTPRequest req,
                                                  ChunkCallback on_chunk)
{
    co_return co_await impl->start(std::move(req), HTTPMethod::GET,
                                   std::move(on_chunk));
}

Task<E<HTTPResponse>> HTTPSessionAsync::postStream(HTTPRequest req,
                                                   ChunkCallback on_chunk)
{
    co_return co_await impl->start(std::move(req), HTTPMethod::POST,
                                   std::move(on_chunk));
}

std::chrono::duration<long> HTTPSessionAsync::transferTimeout() const
{
    return impl->transferTimeout();
}

E<void> HTTPSessionAsync::transferTimeout(std::chrono::duration<long> t)
{
    return impl->transferTimeout(t);
}

std::chrono::duration<long> HTTPSessionAsync::connectionTimeout() const
{
    return impl->connectionTimeout();
}

E<void> HTTPSessionAsync::connectionTimeout(std::chrono::duration<long> t)
{
    return impl->connectionTimeout(t);
}

long HTTPSessionAsync::maxSize() const
{
    return impl->maxSize();
}

E<void> HTTPSessionAsync::maxSize(long s)
{
    return impl->maxSize(s);
}

long HTTPSessionAsync::maxRedirections() const
{
    return impl->maxRedirections();
}

E<void> HTTPSessionAsync::maxRedirections(long n)
{
    return impl->maxRedirections(n);
}

bool HTTPSessionAsync::followRedirects() const
{
    return impl->followRedirects();
}

void HTTPSessionAsync::followRedirects(bool follow)
{
    impl->followRedirects(follow);
}

const AddressPredicate& HTTPSessionAsync::addressFilter() const
{
    return impl->addressFilter();
}

void HTTPSessionAsync::addressFilter(AddressPredicate pred)
{
    impl->addressFilter(std::move(pred));
}

E<void> HTTPSessionAsync::allowedProtocols(std::string_view protocols)
{
    return impl->allowedProtocols(protocols);
}

E<void> HTTPSessionAsync::allowedRedirectProtocols(std::string_view protocols)
{
    return impl->allowedRedirectProtocols(protocols);
}

} // namespace mw
