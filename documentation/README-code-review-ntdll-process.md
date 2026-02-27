# Code Review: dlls/ntdll/unix/process.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/process.c`

---

## Summary

Five issues were identified. The dominant themes are unchecked `malloc` return
values and missing error handling for system calls whose failures silently
produce wrong program state. The two most consequential are an internal crash
in `build_argv` on allocation failure (before it can even return NULL) and a
silent misdirection of stdin/stdout when `open("/dev/null")` fails inside
`set_stdio_fd`.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Medium | Error handling | 92–93 | Second `malloc` in `build_argv` unchecked; crashes before returning NULL; leaks first allocation |
| 2 | Medium | Error handling | 443, 611 | `build_argv` return value not checked before `exec` in child processes |
| 3 | Medium | Error handling | 379–387 | `open("/dev/null")` unchecked in `set_stdio_fd`; `dup2(-1, fd)` silently no-ops |
| 4 | Medium | Error handling | 550–551 | `malloc` unchecked in `wow64_wine_spawnvp`; loop immediately dereferences NULL |
| 5 | Low | Error handling | 813 | `setsockopt(SO_PASSCRED)` return value discarded in `NtCreateUserProcess` |

---

## Issue 1 — Medium: Second `malloc` in `build_argv` unchecked; internal crash before NULL return

**Lines**: 92–93
**Function**: `build_argv`

### Code

```c
/* line 87 — first allocation (correctly checked) */
if (!(src = malloc( len * 3 + 1 ))) return NULL;
len = ntdll_wcstoumbs( cmdline->Buffer, len, src, len * 3, FALSE );
src[len++] = 0;

/* line 91-93 — second allocation (unchecked) */
argc = reserved + 2 + len / 2;
argv = malloc( argc * sizeof(*argv) + len );   /* return value not checked */
arg = dst = (char *)(argv + argc);             /* crash if argv == NULL */
```

### Problem

The first `malloc` (line 87) is correctly guarded and returns `NULL` to callers
on failure. The second `malloc` (line 92) is not guarded. Line 93 immediately
performs pointer arithmetic on the result (`argv + argc`), which is undefined
behaviour when `argv` is `NULL` — in practice a NULL dereference crash.

The function never reaches its `return NULL` error path: callers that check the
return value for `NULL` cannot defend against this failure because the crash
happens inside `build_argv` before any return.

Additionally, `src` — allocated successfully on line 87 — is never freed before
the crash, producing a small heap leak in the dying process.

### Fix

```c
argv = malloc( argc * sizeof(*argv) + len );
if (!argv) { free( src ); return NULL; }
arg = dst = (char *)(argv + argc);
```

---

## Issue 2 — Medium: `build_argv` return not checked before `exec` in child processes

**Lines**: 443, 611
**Functions**: `spawn_process` (line 443), `fork_and_exec` (line 611)

### Code

```c
/* spawn_process child, line 443 */
argv = build_argv( &params->CommandLine, 2 );
exec_wineloader( argv, socketfd, pe_info );
_exit(1);

/* fork_and_exec grandchild, line 611 */
argv = build_argv( &params->CommandLine, 0 );
if (unixdir != -1) { fchdir( unixdir ); close( unixdir ); }
execv( unix_name, argv );
```

### Problem

Neither call site checks whether `build_argv` returned `NULL`. After the fix
for Issue 1, `build_argv` can properly return `NULL` on OOM. With a `NULL`
`argv`:

- `exec_wineloader(NULL, ...)` passes `NULL` as the argument vector to
  `execve`, which returns `EFAULT`. The child falls through to `_exit(1)`
  with no diagnostic message.
- `execv(unix_name, NULL)` similarly fails with `EFAULT`, again with no
  diagnostic.

In both cases the child exits silently with status 1, causing the parent to
observe an unexplained process-creation failure.

### Fix

```c
/* spawn_process */
argv = build_argv( &params->CommandLine, 2 );
if (!argv) _exit(1);   /* OOM in child; parent sees fork failure */
exec_wineloader( argv, socketfd, pe_info );
_exit(1);

/* fork_and_exec */
argv = build_argv( &params->CommandLine, 0 );
if (!argv) { write_error( ENOMEM ); _exit(1); }
```

Or, more informatively, log an error before `_exit` so the failure is visible
in the Wine debug output.

---

## Issue 3 — Medium: `open("/dev/null")` unchecked in `set_stdio_fd`; `dup2(-1, fd)` silently fails

**Lines**: 379–387
**Function**: `set_stdio_fd`

### Code

```c
static void set_stdio_fd( int stdin_fd, int stdout_fd )
{
    int fd = -1;

    if (stdin_fd == -1 || stdout_fd == -1)
    {
        fd = open( "/dev/null", O_RDWR );   /* unchecked */
        if (stdin_fd == -1) stdin_fd = fd;  /* fd may be -1 on failure */
        if (stdout_fd == -1) stdout_fd = fd;
    }

    if (stdin_fd != 0) dup2( stdin_fd, 0 );  /* dup2(-1, 0) if open failed */
    if (stdout_fd != 1) dup2( stdout_fd, 1 );
    if (fd != -1) close( fd );
}
```

### Problem

If `open("/dev/null", O_RDWR)` fails, `fd` remains `-1`. The two assignments
propagate this `-1` into `stdin_fd`/`stdout_fd`. The subsequent `dup2(-1, 0)`
and `dup2(-1, 1)` calls return `EBADF` silently, leaving file descriptors 0
and 1 unchanged.

The most consequential path is the daemon / `setsid` branch in `fork_and_exec`
(line 601):

```c
setsid();
set_stdio_fd( -1, -1 );  /* intends to redirect both to /dev/null */
```

If `open` fails, the grandchild's stdin and stdout remain pointing to the
original terminal or pipe. The grandchild then executes a Unix binary with an
unexpected inherited terminal — a resource-leak, potential security concern, and
source of confusing output.

### Fix

```c
fd = open( "/dev/null", O_RDWR );
if (fd == -1) fd = open( "/dev/null", O_WRONLY );  /* last-resort fallback */
/* If still -1, log and continue — nothing useful to do */
if (fd == -1) WARN( "cannot open /dev/null: %s\n", strerror(errno) );
if (stdin_fd == -1) stdin_fd = fd;
if (stdout_fd == -1) stdout_fd = fd;
```

Or simply treat failure as fatal in the process-creation path:

```c
if (fd == -1) _exit(1);
```

---

## Issue 4 — Medium: `malloc` unchecked in `wow64_wine_spawnvp`; loop dereferences NULL

**Lines**: 550–551
**Function**: `wow64_wine_spawnvp`

### Code

```c
while (argv32[count]) count++;
argv = malloc( (count + 1) * sizeof(*argv) );
for (i = 0; i < count; i++) argv[i] = ULongToPtr( argv32[i] );  /* crash if NULL */
argv[count] = NULL;
ret = __wine_unix_spawnvp( argv, params32->wait );
free( argv );
```

### Problem

`malloc` is not checked. If it returns `NULL`, the `for` loop immediately
dereferences `argv[0]` — a NULL pointer write, causing a crash. The function
is called from the 32-bit WoW64 process-spawn path; an OOM here produces a
crash with no diagnostic rather than a clean error status.

### Fix

```c
argv = malloc( (count + 1) * sizeof(*argv) );
if (!argv) return STATUS_NO_MEMORY;
```

---

## Issue 5 — Low: `setsockopt(SO_PASSCRED)` return value discarded

**Line**: 813
**Function**: `NtCreateUserProcess`

### Code

```c
#ifdef SO_PASSCRED
else
{
    int enable = 1;
    setsockopt( socketfd[0], SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable) );
}
#endif
```

### Problem

If `SO_PASSCRED` is available at compile time but `setsockopt` fails at runtime,
credential passing on the socket is silently disabled. This is the same class
of issue as `server.c` Issue 6: the `SCM_CREDENTIALS` handler never fires,
`server_pid` is never set, and the `prctl(PR_SET_PDEATHSIG)` mechanism that
kills Wine threads when the server exits operates with a stale or zero PID.

### Fix

Log a warning so the failure is visible:

```c
if (setsockopt( socketfd[0], SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable) ) == -1)
    WARN( "setsockopt SO_PASSCRED failed: %s\n", strerror(errno) );
```
