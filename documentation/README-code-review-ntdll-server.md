# Code Review: dlls/ntdll/unix/server.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/server.c`

---

## Summary

Six issues were identified ranging from medium-severity error handling gaps to
low-severity code robustness concerns.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Medium | Error handling | 1309–1312 | `asprintf` unchecked; returns NULL on OOM |
| 2 | Medium | IPC correctness | 1008 | `recvmsg` partial-read not detected; handle left uninitialised |
| 3 | Medium | Error handling | 1462 | `fchdir` return value unchecked |
| 4 | Medium | Logic | 1061 | Small handle values wrap unsigned index silently |
| 5 | Low | Code robustness | 1447 | `strcpy` into `sun_path` |
| 6 | Low | Error handling | 1457 | `setsockopt(SO_PASSCRED)` return value unchecked |

---

## Issue 1 — Medium: `asprintf` return value unchecked; NULL returned on OOM

**Lines**: 1309–1312
**Function**: `init_server_dir`

### Code

```c
static const char *init_server_dir( dev_t dev, ino_t ino )
{
    char *dir = NULL;

#ifdef __ANDROID__
    asprintf( &dir, "%s/.wineserver/server-%llx-%llx", config_dir,
              (unsigned long long)dev, (unsigned long long)ino );
#else
    asprintf( &dir, "/tmp/.wine-%u/server-%llx-%llx", getuid(),
              (unsigned long long)dev, (unsigned long long)ino );
#endif
    return dir;      /* returns NULL if asprintf failed */
}
```

### Problem

`asprintf` returns `-1` on allocation failure and leaves `dir` unchanged (still
`NULL`). The function returns `NULL` to its caller, which uses the result as a
path in `chdir` and `open` calls. Those fail with `EFAULT` or `ENOENT`, and
any error message that dereferences the returned pointer will crash the process.
The failure mode produces a confusing crash rather than a diagnostic.

Every other allocation failure in the file calls `fatal_perror` immediately.
This site should be consistent.

### Fix

```c
#ifdef __ANDROID__
    if (asprintf( &dir, "%s/.wineserver/server-%llx-%llx", config_dir,
                  (unsigned long long)dev, (unsigned long long)ino ) == -1)
        fatal_perror( "asprintf" );
#else
    if (asprintf( &dir, "/tmp/.wine-%u/server-%llx-%llx", getuid(),
                  (unsigned long long)dev, (unsigned long long)ino ) == -1)
        fatal_perror( "asprintf" );
#endif
```

---

## Issue 2 — Medium: `recvmsg` partial-read not detected; handle left partially uninitialised

**Line**: 1008
**Function**: `receive_fd`

### Code

```c
vec.iov_base = (void *)handle;
vec.iov_len  = sizeof(*handle);          /* expects exactly 4 bytes */

if ((ret = recvmsg( fd_socket, &msghdr, MSG_CMSG_CLOEXEC )) > 0)
{
    /* ... process ancillary data, return fd ... */
    return fd;
}
```

### Problem

The check `ret > 0` accepts any positive byte count. If `recvmsg` returns 1, 2,
or 3 (a partial read of the 4-byte handle field), the upper bytes of `*handle`
retain whatever value they contained before the call. The function returns the
received file descriptor without signalling that the handle is corrupt.

Every caller that subsequently uses `*handle` operates on a partially
uninitialised value, which can produce wrong cache lookups, bad access checks,
or silent use of incorrect handles.

In practice the wineserver writes the full handle atomically over a UNIX stream
socket on the same machine, so partial reads are extremely unlikely — but the
code should not silently accept them.

### Fix

```c
if ((ret = recvmsg( fd_socket, &msghdr, MSG_CMSG_CLOEXEC )) == (ssize_t)sizeof(*handle))
```

Any other positive value is a protocol error and should be reported via
`server_protocol_error`.

---

## Issue 3 — Medium: `fchdir` return value unchecked after successful connect

**Line**: 1462
**Function**: `connect_to_server`

### Code

```c
if (connect( s, (struct sockaddr *)&addr, slen ) != -1)
{
    fchdir( initial_cwd );   /* switch back to the starting directory */
    fcntl( s, F_SETFD, FD_CLOEXEC );
    return s;
}
```

### Problem

The function temporarily changes to the wineserver directory to connect to the
socket, then calls `fchdir(initial_cwd)` to restore the original working
directory. If `fchdir` fails (for example, if `initial_cwd` was closed or the
fd became invalid), the process silently continues with its working directory
set to the wineserver directory. Any subsequent relative-path operation goes to
the wrong place, causing hard-to-diagnose failures far from the source.

### Fix

Treat failure as fatal, consistent with other initialization errors:

```c
if (fchdir( initial_cwd ) == -1) fatal_perror( "fchdir" );
```

---

## Issue 4 — Medium: Small handle values cause unsigned index wrap-around

**Line**: 1061
**Function**: `handle_to_index`

### Code

```c
static inline unsigned int handle_to_index( HANDLE handle, unsigned int *entry )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    *entry = idx / FD_CACHE_BLOCK_SIZE;
    return idx % FD_CACHE_BLOCK_SIZE;
}
```

### Problem

If `wine_server_obj_handle(handle)` is 0, 1, 2, or 3 (invalid or pseudo-handle
values passed by a caller in error), the right shift produces 0, and subtracting
1 from an unsigned zero wraps to `0xFFFFFFFF`. The resulting `*entry` is
enormous.

The bounds check in `add_fd_to_cache` and `get_cached_fd`
(`if (entry >= FD_CACHE_ENTRIES)`) catches this and rejects the handle, so no
out-of-bounds memory access occurs. However, the rejection is silent: callers
receive a `FALSE` return or a cache miss with no indication that the handle was
invalid rather than merely uncached. This masks caller bugs where a bad handle
is passed.

### Fix

Detect the invalid case before the arithmetic:

```c
static inline unsigned int handle_to_index( HANDLE handle, unsigned int *entry )
{
    unsigned int raw = wine_server_obj_handle(handle) >> 2;
    if (!raw) { *entry = FD_CACHE_ENTRIES; return 0; }  /* force bounds-check failure */
    unsigned int idx = raw - 1;
    *entry = idx / FD_CACHE_BLOCK_SIZE;
    return idx % FD_CACHE_BLOCK_SIZE;
}
```

---

## Issue 5 — Low: `strcpy` into fixed-size `sun_path`

**Line**: 1447
**Function**: `connect_to_server`

### Code

```c
addr.sun_family = AF_UNIX;
strcpy( addr.sun_path, SOCKETNAME );
```

### Problem

`SOCKETNAME` is the compile-time literal `"socket"` (7 bytes) and `sun_path`
is 108 bytes on Linux, so no overflow occurs today. However, `strcpy` into a
fixed-size field is fragile: if `SOCKETNAME` is ever changed without auditing
this site, the overflow will be silent and potentially exploitable.

Using `snprintf` makes the safety bound self-documenting and compiler-verifiable.

### Fix

```c
snprintf( addr.sun_path, sizeof(addr.sun_path), "%s", SOCKETNAME );
```

---

## Issue 6 — Low: `setsockopt(SO_PASSCRED)` return value discarded

**Line**: 1457
**Function**: `connect_to_server`

### Code

```c
#ifdef SO_PASSCRED
else
{
    int enable = 1;
    setsockopt( s, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable) );
}
#endif
```

### Problem

If `SO_PASSCRED` is available at compile time but `setsockopt` fails at runtime,
credential passing is silently disabled. The `SCM_CREDENTIALS` handler at line
1016 then never fires, `server_pid` is never populated, and the later
`prctl(PR_SET_PDEATHSIG)` call at line 1657 operates with a stale or zero PID —
silently breaking the death-signal mechanism that ensures Wine threads are
cleaned up when the server exits.

### Fix

Log a warning on failure so the problem is visible:

```c
if (setsockopt( s, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable) ) == -1)
    WARN( "setsockopt SO_PASSCRED failed: %s\n", strerror(errno) );
```
