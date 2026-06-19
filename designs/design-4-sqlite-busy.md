# Add SQLITE_BUSY handling (busy_timeout + retry) to libmw's SQLite wrapper

## Context

`libmw` (this repo, `~/programs/libmw`) wraps SQLite behind the `mw::SQLite` /
`mw::SQLiteStatement` classes:
- Public header: `includes/mw/database.hpp`
- Implementation: `sqlite/src/database.cpp`
- Tests: `sqlite/src/database_test.cpp`

It already enables WAL on connect (`PRAGMA journal_mode = WAL`) and opens the DB
with SQLite's default serialized threading mode. Error handling uses `mw::E<>`
(see `error.hpp`, macros `DO_OR_RETURN` / `ASSIGN_OR_RETURN`).

A downstream project (an ActivityPub server) runs **background job-queue
workers and web request handlers concurrently**, each on its own `mw::SQLite`
connection to the same database file. With WAL, SQLite allows one writer at a
time; concurrent writers collide and return `SQLITE_BUSY`. The wrapper currently
mishandles this:

1. **No `busy_timeout` is set on connect** — a contended writer gets
   `SQLITE_BUSY` immediately instead of waiting for the lock.
2. **`SQLITE_BUSY` is a hard, non-retried failure.** In `SQLite::eval()`
   (template in `database.hpp`) the step loop does:
   ```cpp
   case SQLITE_BUSY:
       sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
       return std::unexpected(runtimeError(sqlite3_errstr(code)));
   ```
   so any transient lock contention surfaces as a spurious error to the caller.

## Goal

Make concurrent access from multiple `mw::SQLite` connections to the same WAL
database robust: contended operations should wait and/or retry instead of
failing spuriously, while genuine errors still propagate.

## Required changes

1. **Set a busy timeout on every connection.** In `SQLite::connectFile()`
   (`sqlite/src/database.cpp`), after opening the DB, call
   `sqlite3_busy_timeout(db, <ms>)` (equivalently `PRAGMA busy_timeout`). This
   lets SQLite block-and-wait on a locked DB up to the timeout before returning
   `SQLITE_BUSY`.
   - Make the timeout **configurable** rather than hardcoded: add an optional
     parameter to `connectFile()` (e.g. `int busy_timeout_ms = 5000`) with a
     sensible default, threaded through `connectMemory()` as well. Keep the
     existing call sites source-compatible (default argument).

2. **Bounded retry-with-backoff on `SQLITE_BUSY` (and `SQLITE_LOCKED`).** In the
   `eval()` step loop, instead of immediately rolling back and failing on
   `SQLITE_BUSY`, retry the statement a bounded number of times with a short
   backoff (e.g. a few milliseconds, optionally increasing), then fail with a
   clear error only after exhausting retries.
   - Use `sqlite3_reset()` on the statement before re-stepping a retry so the
     statement can run again. Be careful: rows already pushed into the result
     vector during a partial scan must not be duplicated — retry semantics are
     cleanest for statements that haven't yet produced rows. A safe approach is
     to only retry when `SQLITE_BUSY` occurs before any `SQLITE_ROW` has been
     consumed for this execution; if it happens mid-iteration, reset accumulated
     results before retrying, or document/limit the behavior. Pick the simplest
     correct approach and note the choice in a comment.
   - Also handle `SQLITE_LOCKED` similarly where appropriate.
   - The retry count and backoff should be reasonable constants (or
     configurable on the `SQLite` object). The `busy_timeout` from step 1 is the
     primary wait mechanism; the retry loop is a backstop for cases the timeout
     doesn't cover.
   - Reconsider the current `ROLLBACK` on `SQLITE_BUSY`: rolling back an
     enclosing transaction the caller started is surprising. Don't silently roll
     back the caller's transaction inside `eval()`; let the caller decide.
     (Confirm this matches how transactions are used elsewhere in the codebase
     before changing it.)

3. Keep `execute()` / `evalToValue()` behavior consistent — they delegate to
   `eval()`, so they inherit the retry automatically; just verify nothing else
   special-cases `SQLITE_BUSY`.

## Constraints / style

- Match existing libmw conventions and the `mw::E<>` error pattern; no
  exceptions. Prefer `unique_ptr` over `shared_ptr`.
- Keep the public header free of leaking new platform headers; the retry/backoff
  is internal to the wrapper.
- Don't change the threading model assumption documented on `class SQLite`
  (serialized; an object may be shared across threads). The fix targets the
  *separate-connection* concurrency case.

## Acceptance

- `connectFile()` sets a configurable busy timeout (default ~5000 ms);
  `connectMemory()` still works.
- Two `mw::SQLite` connections to the same on-disk WAL database performing
  concurrent writes do not produce spurious `SQLITE_BUSY` errors under normal
  contention; one waits/retries and both eventually succeed.
- Genuine, non-transient errors still propagate as `mw::E<>` failures.
- Existing tests in `sqlite/src/database_test.cpp` pass; add a test exercising
  concurrent writers on a temp on-disk DB (two connections, interleaved
  transactions) that would previously have hit `SQLITE_BUSY`.
