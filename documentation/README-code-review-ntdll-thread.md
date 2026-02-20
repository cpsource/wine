# Code Review: dlls/ntdll/unix/thread.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/thread.c`

---

## Summary

Six issues were identified ranging from a high-severity race condition to
low-severity correctness gaps in stub and context-conversion code.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | High | Race condition | 1495–1513 | `exit_thread` `prev_teb` slot races under concurrent exit |
| 2 | Medium | Logic | 779–782, 907–910 | Missing `ContextFlags` update in cross-arch context conversions |
| 3 | Medium | Input validation | 2018, 2077–2078 | `ntdll_wcstoumbs` return unchecked before use as write count / array index |
| 4 | Medium | Signal safety | 1476 | `abort_thread` calls `pthread_sigmask` — not async-signal-safe |
| 5 | Low | Correctness | 625–627 | ARM64↔I386 context conversion silently succeeds without converting any data |
| 6 | Low | Dead code | 1316–1323 | `NtCreateThread` is an unimplemented stub that can never be called usefully |

---

## Issue 1 — High: Race condition in `exit_thread` `prev_teb` cleanup

**Lines**: 1495–1513
**Function**: `exit_thread`

### Code

```c
static void *prev_teb;
...
if ((teb = InterlockedExchangePointer( &prev_teb, NtCurrentTeb() )))
{
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;

    if (thread_data->pthread_id)
    {
        pthread_join( thread_data->pthread_id, NULL );
        virtual_free_teb( teb );
    }
}
pthread_exit_wrapper( status );
```

### Problem

The design stores only one TEB at a time in `prev_teb`. When thread A exits it
swaps its own TEB into `prev_teb` and joins/frees whatever was there before.
If threads A and B exit concurrently:

1. Thread A does `InterlockedExchange(&prev_teb, A_teb)` → gets NULL (slot was
   empty), does nothing for A's cleanup.
2. Thread B does `InterlockedExchange(&prev_teb, B_teb)` → gets `A_teb`,
   joins A's pthread and frees A's TEB.
3. Thread A's TEB remains in `prev_teb` after B exits.
4. If no further thread exits, A's TEB is never freed (leaked).

With three or more concurrent exits the situation worsens: the thread that last
writes `prev_teb` always leaves its own TEB in the slot un-freed. Every TEB
leak is a fixed-size anonymous mapping (tens of kilobytes) that persists for
the process lifetime.

### Fix

Use a proper cleanup mechanism that does not limit in-flight frees to one slot:
a lock-protected list, a dedicated cleanup thread, or a `pthread_key_t`
destructor that frees each TEB as the corresponding thread exits.

---

## Issue 2 — Medium: Missing `ContextFlags` update in cross-arch context conversions

**Lines**: 779–782, 907–910
**Functions**: `context_from_server` (x86_64→i386 and i386→x86_64 paths)

### Code

```c
/* x86_64 → i386 path (line 779) */
if ((from->flags & SERVER_CTX_INTEGER) && (to_flags & CONTEXT_I386_CONTROL))
{
    to->Ebp = from->integer.x86_64_regs.rbp;
    /* ContextFlags NOT updated */
}

/* i386 → x86_64 path (line 907) */
if ((from->flags & SERVER_CTX_CONTROL) && (to_flags & CONTEXT_AMD64_INTEGER))
{
    to->Rbp = from->ctl.i386_regs.ebp;
    /* ContextFlags NOT updated */
}
```

### Problem

Every other branch in `context_from_server` updates `to->ContextFlags` with
the flag that indicates the copied registers are now valid (e.g.
`to->ContextFlags |= CONTEXT_I386_INTEGER`). These two branches copy `Ebp`
(x86_64→i386) and `Rbp` (i386→x86_64) into the destination context but omit
the flag update.

A caller that checks `ContextFlags` before reading `Ebp`/`Rbp` will see the
flag absent and treat the register as invalid, silently ignoring the freshly
copied value. This can produce incorrect debugger views and wrong exception
dispatch behaviour.

### Fix

Add the missing flag updates:

```c
/* x86_64 → i386 path */
if ((from->flags & SERVER_CTX_INTEGER) && (to_flags & CONTEXT_I386_CONTROL))
{
    to->ContextFlags |= CONTEXT_I386_CONTROL;
    to->Ebp = from->integer.x86_64_regs.rbp;
}

/* i386 → x86_64 path */
if ((from->flags & SERVER_CTX_CONTROL) && (to_flags & CONTEXT_AMD64_INTEGER))
{
    to->ContextFlags |= CONTEXT_AMD64_INTEGER;
    to->Rbp = from->ctl.i386_regs.ebp;
}
```

---

## Issue 3 — Medium: `ntdll_wcstoumbs` return unchecked before use

**Lines**: 2018, 2077–2078
**Function**: `set_native_thread_name`

### Code

```c
/* Linux path (line 2018) */
len = ntdll_wcstoumbs( name->Buffer, name->Length / sizeof(WCHAR),
                       nameA, sizeof(nameA), FALSE );
...
write( fd, nameA, len );

/* BSD/macOS path (lines 2077-2078) */
len = ntdll_wcstoumbs( name->Buffer, name->Length / sizeof(WCHAR),
                       nameA, sizeof(nameA), FALSE );
nameA[len] = '\0';
```

### Problem

`ntdll_wcstoumbs` documents that it returns the number of bytes written to the
output buffer on success, or `-1` if the output buffer is too small to hold any
output. Two failure modes are not guarded:

1. **Return value `-1`**: On the Linux path `write(fd, nameA, (size_t)-1)` is
   called with a count of `SIZE_MAX`, which will fail with `EINVAL` or `EFAULT`
   but wastes a syscall and is confusing. On the BSD path `nameA[-1] = '\0'`
   is an out-of-bounds write before the buffer — undefined behaviour.

2. **Return value `sizeof(nameA)`** (buffer exactly full, no room for NUL): On
   the BSD path `nameA[sizeof(nameA)] = '\0'` writes one byte past the end of
   the array — an off-by-one buffer overflow.

### Fix

```c
len = ntdll_wcstoumbs( name->Buffer, name->Length / sizeof(WCHAR),
                       nameA, sizeof(nameA) - 1, FALSE );
if (len < 0) return;
nameA[len] = '\0';
```

Reducing the limit by one guarantees space for the terminator and prevents the
off-by-one. Checking `len < 0` guards the error path.

---

## Issue 4 — Medium: `abort_thread` calls `pthread_sigmask` — not async-signal-safe

**Line**: 1476
**Function**: `abort_thread`

### Code

```c
void abort_thread( int status )
{
    pthread_sigmask( SIG_BLOCK, &server_block_set, NULL );
    if (InterlockedDecrement( &nb_threads ) <= 0) abort_process( status );
    pthread_exit_wrapper( status );
}
```

### Problem

`pthread_sigmask` is not in the POSIX list of async-signal-safe functions. If
`abort_thread` is reached from a signal handler (e.g. via the SIGSEGV/SIGBUS
fault path or from `raise()` inside a signal), calling `pthread_sigmask` there
is undefined behaviour: the function may acquire an internal lock that the
interrupted thread already holds, causing a deadlock.

### Fix

Use `sigprocmask` (which on Linux with pthreads behaves identically in
single-threaded contexts and is async-signal-safe) or restructure so that
`abort_thread` is never called from signal context. The function already calls
`pthread_exit_wrapper` which is also not async-signal-safe, so a larger
refactor may be needed to make the signal-handler abort path fully safe.

---

## Issue 5 — Low: ARM64↔I386 context conversion silently returns SUCCESS

**Lines**: 625–627
**Function**: `context_from_server`

### Code

```c
case MAKELONG( IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386 ):
case MAKELONG( IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64 ):
    return STATUS_SUCCESS;
```

### Problem

These two cases claim success but convert nothing: `to->ContextFlags` is never
set, and no registers are copied. Any caller that inspects the output context
after this call operates on a zeroed or uninitialised structure while believing
the conversion succeeded.

If ARM64↔I386 cross-architecture context translation is genuinely unsupported,
the correct return value is `STATUS_INVALID_PARAMETER` (consistent with the
`default` branch directly below). Returning `STATUS_SUCCESS` with no output is
a silent lie.

### Fix

```c
case MAKELONG( IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386 ):
case MAKELONG( IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64 ):
    return STATUS_INVALID_PARAMETER;
```

---

## Issue 6 — Low: `NtCreateThread` is an unimplemented stub

**Lines**: 1316–1323
**Function**: `NtCreateThread`

### Code

```c
NTSTATUS WINAPI NtCreateThread( HANDLE *handle, ACCESS_MASK access,
                                OBJECT_ATTRIBUTES *attr, HANDLE process,
                                CLIENT_ID *id, CONTEXT *ctx, INITIAL_TEB *teb,
                                BOOLEAN suspended )
{
    FIXME( "%p %d %p %p %p %p %p %d, stub!\n",
           handle, access, attr, process, id, ctx, teb, suspended );
    return STATUS_NOT_IMPLEMENTED;
}
```

### Problem

`NtCreateThread` is the pre-Vista NT thread creation API. It has never been
implemented in Wine; `NtCreateThreadEx` (immediately below) is the functional
replacement. Because `NtCreateThread` unconditionally returns
`STATUS_NOT_IMPLEMENTED`, any caller relying on the old API fails silently with
no path forward.

The Windows DDK marks `NtCreateThread` as deprecated in favour of
`NtCreateThreadEx`, and no modern application is expected to call it directly.
However, the stub is exported and advertises itself as callable.

### Note

This is existing technical debt rather than a newly introduced defect. It is
documented here for completeness and for tracking purposes.
