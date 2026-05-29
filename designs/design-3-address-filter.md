# Add SSRF-protection hook to the libcurl wrapper in libmw

## Context

`libmw` (https://github.com/MetroWind/libmw) wraps libcurl behind an HTTP
client interface (see `includes/mw/http_client.hpp` — `HTTPSessionInterface`,
`HTTPRequest`, `HTTPResponse`, and the concrete libcurl-backed session). It
uses `mw::E<>` for error handling rather than exceptions.

A downstream project (an ActivityPub server) makes outbound HTTP requests to
URLs supplied by *remote, untrusted servers* (actor resolution, thread fetch,
WebFinger). This is a classic SSRF surface: a hostile server can return a URL
whose hostname resolves to an internal/loopback/link-local/cloud-metadata
address (e.g. `127.0.0.1`, `::1`, `10.0.0.0/8`, `192.168.0.0/16`,
`169.254.0.0/16`, `fd00::/8`, `169.254.169.254`). The wrapper currently has no
way for a caller to reject such destinations.

## Goal

Extend the libcurl wrapper so callers can **validate the actual resolved
destination address before a connection is made**, and abort the request if the
address is disallowed. This must be rebinding-proof (no TOCTOU window) and must
also apply to addresses reached via HTTP redirects.

## Required approach

Use libcurl's connect-time callback rather than pre-resolving DNS in the
caller:

- Set `CURLOPT_OPENSOCKETFUNCTION` (and `CURLOPT_OPENSOCKETDATA`). libcurl
  invokes this with the exact `struct sockaddr` it is about to connect to,
  *after* its own DNS resolution. The callback validates that address and, to
  block, returns `CURL_SOCKET_BAD` (which aborts the connection). Because the
  callback sees the precise address curl will use, there is no separate resolve
  step and therefore no DNS-rebinding window. It fires for every connection,
  including each redirect hop, so redirects are covered automatically.
  - (`CURLOPT_SOCKOPTFUNCTION` is an alternative place to inspect/abort; pick
    whichever integrates more cleanly. The open-socket callback is preferred.)

Expose this to callers via a clean abstraction — do NOT leak raw libcurl types
into the public interface. Suggested shape (adapt to libmw conventions):

- A caller-supplied predicate, e.g.
  `std::function<bool(const SockAddr&)>` or
  `std::function<mw::E<void>(const SockAddr&)>`, settable on the request or the
  session, where returning false / an error blocks the connection. Provide a
  small public `SockAddr`-like struct (family + IP bytes + port) so callers can
  do range checks without touching `<sys/socket.h>` / curl headers.
- When a connection is blocked by the predicate, the request should fail with a
  clear `mw::E<>` error (distinct enough that the caller can tell it was an
  SSRF/policy block vs. a network error).

While here, also expose (if not already available) the related hardening
options so the downstream policy can be fully expressed:

- Restrict allowed protocols: `CURLOPT_PROTOCOLS_STR` and
  `CURLOPT_REDIR_PROTOCOLS_STR` (caller wants to allow `https` only).
- Redirect following + cap: `CURLOPT_FOLLOWLOCATION` and `CURLOPT_MAXREDIRS`.

## Notes / constraints

- Match existing libmw style and the `mw::E<>` error pattern; prefer
  `unique_ptr` over `shared_ptr`.
- Keep the public header free of libcurl includes.
- The callback runs inside libcurl; keep it cheap and non-throwing.
- IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) must be handled — normalize
  before range checks so they can't be used to bypass the IPv4 blocklist. (If
  you expose raw address bytes to the caller, document this so the *caller's*
  predicate can handle it; otherwise normalize in the wrapper.)

## Acceptance

- A caller can install an address predicate on an HTTP session/request, and a
  request to a host that resolves to a blocked address fails before any data is
  sent, with a distinguishable error.
- The predicate is consulted again for each redirect hop.
- `https`-only protocol restriction and a redirect cap are settable through the
  public interface.
- Existing HTTP client tests still pass; add a test that an installed predicate
  rejecting a loopback address causes the request to fail. (A loopback test
  server bound to `127.0.0.1` whose predicate rejects loopback is a simple way
  to exercise the abort path.)
