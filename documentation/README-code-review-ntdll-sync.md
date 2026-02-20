# Code Review: dlls/ntdll/unix/sync.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/sync.c`

---

## Summary

Four issues were identified: two medium-severity correctness bugs and two
low-severity issues. The most notable are a signed-integer overflow in the
ntsync timeout conversion path and a race condition in the inproc-sync cache
block allocator.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Medium | Integer overflow | 415, 419 | Signed ×100 overflow in `linux_wait_objs` timeout arithmetic |
| 2 | Medium | Race condition | 579–587 | Unprotected block allocation in `cache_inproc_sync` leaks on concurrent miss |
| 3 | Low | Input validation | 1767 | `nb_params` not validated client-side before writing `ExceptionInformation` |
| 4 | Low | Logic | 84–85 | Negative modulo in `debugstr_timeout` for relative timeouts |

---

## Issue 1 — Medium: Signed ×100 overflow in `linux_wait_objs` timeout arithmetic

**Lines**: 415, 419
**Function**: `linux_wait_objs`

### Code

```c
/* relative timeout path (line 415) */
args.timeout = ((ULONGLONG)now.tv_sec * NSECPERSEC) + now.tv_nsec
             + (-timeout->QuadPart * 100);

/* absolute timeout path (line 419) */
args.timeout = (timeout->QuadPart * 100) - (SECS_1601_TO_1970 * NSECPERSEC);
```

### Problem

`timeout->QuadPart` is a `LONGLONG`. Both multiplications (`* 100`) are
evaluated as **signed** 64-bit arithmetic before the result is widened to
`ULONGLONG` (the type of `args.timeout`). If `timeout->QuadPart` is large
enough in magnitude, the intermediate product overflows `LONGLONG` and the
behaviour is undefined; the resulting `args.timeout` passed to the kernel is
then a small or nonsensical value.

**Relative path** (line 415): `-timeout->QuadPart * 100` overflows when
`-timeout->QuadPart > LLONG_MAX / 100`, i.e. when the requested delay
exceeds roughly 29 247 years — theoretically reachable if a caller passes
`LLONG_MIN` as the timeout.

**Absolute path** (line 419): `timeout->QuadPart * 100` overflows for
absolute timestamps after approximately the year 4384 (FILETIME epoch).

In both cases the overflow corrupts the nanosecond deadline sent to the
`NTSYNC_IOC_WAIT_ANY/WAIT_ALL` ioctl, causing the wait to expire far too
early or at the wrong absolute time.

### Fix

Cast to `ULONGLONG` before multiplying to perform unsigned arithmetic:

```c
/* relative path */
args.timeout = ((ULONGLONG)now.tv_sec * NSECPERSEC) + now.tv_nsec
             + ((ULONGLONG)(-timeout->QuadPart) * 100);

/* absolute path */
args.timeout = ((ULONGLONG)timeout->QuadPart * 100)
             - (SECS_1601_TO_1970 * NSECPERSEC);
```

---

## Issue 2 — Medium: Unprotected block allocation in `cache_inproc_sync` races under concurrent cache miss

**Lines**: 579–587
**Function**: `cache_inproc_sync`

### Code

```c
if (!inproc_sync_cache[entry])  /* do we need to allocate a new block? */
{
    if (!entry) inproc_sync_cache[0] = inproc_sync_cache_initial_block;
    else
    {
        static const size_t size = INPROC_SYNC_CACHE_BLOCK_SIZE * sizeof(struct inproc_sync);
        void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
        if (ptr == MAP_FAILED) return sync;
        inproc_sync_cache[entry] = ptr;   /* plain store, no CAS */
    }
}
```

### Problem

The check and the store are not atomic. Two threads can simultaneously
observe `inproc_sync_cache[entry] == NULL`, both call `anon_mmap_alloc`,
and both store their pointer. The second store silently overwrites the first:
the mapping allocated by the first thread is permanently leaked (it has no
remaining pointer and can never be `munmap`ed).

Under memory pressure — the most likely scenario for `anon_mmap_alloc` to
be called for new cache blocks — leaking entire anonymous mappings makes
subsequent allocations even harder.

The remainder of the function (`cache` assignment at line 591 and the
`InterlockedCompareExchange` at line 593) uses proper atomics, making this
unprotected allocation stand out as inconsistent.

### Fix

Use `InterlockedCompareExchangePointer` so only one thread's allocation
survives and the loser is freed immediately:

```c
void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
if (ptr == MAP_FAILED) return sync;
if (InterlockedCompareExchangePointer(
        (void **)&inproc_sync_cache[entry], ptr, NULL ) != NULL)
    munmap( ptr, size );  /* another thread beat us to it */
```

---

## Issue 3 — Low: `nb_params` not validated client-side before writing `ExceptionInformation`

**Line**: 1767
**Function**: `event_data_to_state_change`

### Code

```c
info->ExceptionRecord.NumberParameters = data->exception.nb_params;
for (i = 0; i < data->exception.nb_params; i++)
    info->ExceptionRecord.ExceptionInformation[i] = data->exception.params[i];
```

### Problem

`ExceptionInformation` is declared as
`ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS]` (15 elements
on Windows). `data->exception.nb_params` comes from the wineserver reply
buffer and is `int`.

The server does cap the value (`server/debugger.c:151`:
`min(nb_params, EXCEPTION_MAXIMUM_PARAMETERS)`), so this cannot be triggered
through a correctly operating server. However, the client has no independent
guard: a malformed or hypothetically fuzzed reply with `nb_params > 15`
would write up to ~120 bytes past the end of `ExceptionInformation`, into
adjacent members of `DBGKM_EXCEPTION` or beyond.

### Fix

Add a client-side clamp to mirror the server's own guard:

```c
info->ExceptionRecord.NumberParameters =
    min( data->exception.nb_params, EXCEPTION_MAXIMUM_PARAMETERS );
for (i = 0; i < info->ExceptionRecord.NumberParameters; i++)
    info->ExceptionRecord.ExceptionInformation[i] = data->exception.params[i];
```

---

## Issue 4 — Low: Negative modulo in `debugstr_timeout` for relative timeouts

**Lines**: 84–85
**Function**: `debugstr_timeout`

### Code

```c
return wine_dbg_sprintf( "%lld.%07ld",
    (long long)(timeout->QuadPart / TICKSPERSEC),
    (long)(timeout->QuadPart % TICKSPERSEC) );
```

### Problem

A relative timeout has a **negative** `QuadPart`. In C, the result of
`%` on a negative dividend is implementation-defined in C99 and negative
in C11/C++11 (truncation towards zero). For a `QuadPart` of, say,
`-15 000 000` (1.5 seconds relative):

```
QuadPart / TICKSPERSEC  →  -1   (seconds part, correct sign)
QuadPart % TICKSPERSEC  →  -5 000 000   (negative remainder)
```

`%07ld` of `-5000000` prints `-5000000` — eight characters instead of
seven, breaking the fixed-width display. More importantly, both parts carry
a minus sign independently, producing output like `-1.-5000000` instead of
the intended `-1.5000000`.

### Fix

Use the absolute value of the fractional part:

```c
return wine_dbg_sprintf( "%lld.%07lld",
    (long long)(timeout->QuadPart / TICKSPERSEC),
    (long long)llabs( timeout->QuadPart % TICKSPERSEC ) );
```
