# Code Review: dlls/ntdll/unix/serial.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/serial.c`

---

## Summary

One issue was identified. A second candidate was rejected as a false positive
after manual verification:

- *Missing `release_fileio` before `goto out_now` (lines 1179–1185)* — the
  `out_now` label is reached only before `server_async` is called (line 1190),
  so the async I/O has not yet been registered with the server. `free(commio)`
  is the correct cleanup at that point; `release_fileio` is only needed after
  the server has taken ownership.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Low | Error handling | 1138 | `wait_on` | `commio->evtmask` read before initialisation — UB in ternary |

---

## Issue 1 — `wait_on`: `commio->evtmask` read before initialisation

**Line**: 1138
**Function**: `wait_on`

### Code

```c
commio->events = out_buffer;
commio->pending_write = 0;
/* commio->evtmask is never initialised here */
status = get_wait_mask( handle, &commio->evtmask,
    (commio->evtmask & EV_TXEMPTY) ? &commio->pending_write : NULL );
```

### Problem

`alloc_fileio` (file.c line 5561) uses `malloc`, not `calloc`, so the
allocated memory is uninitialised. Only `events` and `pending_write` are set
before line 1138; `evtmask` is not. The ternary expression
`(commio->evtmask & EV_TXEMPTY)` therefore reads an indeterminate value —
undefined behaviour. A sufficiently aggressive compiler is free to produce
unexpected code around the UB.

In practice, if the garbage value happens to have `EV_TXEMPTY` set, the
server is asked for `SERIALINFO_PENDING_WRITE` unnecessarily (or vice-versa).
The correct behaviour is to always ask for `pending_write` alongside the
event mask, or restructure the call.

The same call at line 1113 (inside `async_wait_proc`) uses an already-populated
`evtmask` and is correct.

### Fix

Remove the ternary; always pass `&commio->pending_write` so that both the
event mask and the pending-write count are fetched in a single server round-trip:

```c
status = get_wait_mask( handle, &commio->evtmask, &commio->pending_write );
```
