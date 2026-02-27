# Code Review: dlls/ntdll/unix/signal_x86_64.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/signal_x86_64.c`

---

## Summary

Six issues were identified ranging from a high-severity async-signal-safety bug
to low-severity synchronisation and defensive-programming concerns.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | High | Signal safety | 2581–2583 | `int_handler` calls `NtCreateThreadEx`/`NtClose` — not async-signal-safe |
| 2 | Medium | Error handling | 2845 | `anon_mmap_fixed` return value unchecked |
| 3 | Medium | Code clarity | 2877–2880 | SIGILL/SIGBUS silently inherit `segv_handler` |
| 4 | Medium | Logic | 1606 | Stack size calculation wraps on corrupted RSP |
| 5 | Low | Signal safety | various | `assert` calls `abort` from inside signal handlers |
| 6 | Low | Concurrency | 2285+ | `instrumentation_callback` read without memory barrier |

---

## Issue 1 — High: `int_handler` calls non-async-signal-safe functions

**Lines**: 2581–2583
**Function**: `int_handler`

### Code

```c
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = init_handler( sigcontext );
    HANDLE handle;

    if (p__wine_ctrl_routine)
    {
        if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                               p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
            NtClose( handle );
    }
    leave_handler( ucontext );
}
```

### Problem

`NtCreateThreadEx` and `NtClose` are not async-signal-safe. Both functions may
acquire internal locks — the heap allocator, the server connection mutex, the
file-descriptor table lock — during normal execution. If SIGINT is delivered
while the interrupted thread already holds any of those locks, the signal
handler will block waiting to re-acquire them, and the thread will deadlock.

POSIX defines only a small set of functions as safe to call from a signal
handler (`write`, `_exit`, `sem_post`, and a handful of others). Thread
creation is not among them.

This is the most dangerous issue in the file. A Ctrl+C at an unlucky moment —
inside a heap allocation, a wineserver round-trip, or any other locked section
— silently hangs the entire Wine process. The bug is latent and triggered by
normal user interaction.

### Suggested approach

Defer the thread creation to a non-signal context. The canonical pattern is to
set a `volatile sig_atomic_t` flag in the handler and have a dedicated thread
(or the main loop) act on it:

```c
static volatile sig_atomic_t ctrl_c_pending;

static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = init_handler( sigcontext );
    if (p__wine_ctrl_routine) ctrl_c_pending = 1;
    leave_handler( ucontext );
}
```

A separate thread blocks on `ctrl_c_pending` (or a `pipe`/`eventfd` written
from the handler) and performs the `NtCreateThreadEx` call safely.

---

## Issue 2 — Medium: `anon_mmap_fixed` return value unchecked

**Line**: 2845
**Function**: `signal_init_process`

### Code

```c
/* sneak in a syscall dispatcher pointer at a fixed address (7ffe1000) */
ptr = (char *)user_shared_data + page_size;
anon_mmap_fixed( ptr, page_size, PROT_READ | PROT_WRITE, 0 );  // return ignored
*(void **)ptr = __wine_syscall_dispatcher;                       // crash if mmap failed
```

### Problem

If `anon_mmap_fixed` fails — because the address is already mapped, the
process is out of address space, or the kernel refuses the fixed mapping —
`ptr` is not backed by physical memory. The immediately following write
dereferences an unmapped address and crashes during process initialisation,
producing a confusing segfault rather than a diagnostic error message.

Every `sigaction` call in the same function is guarded with `goto error`. This
mmap call should be too.

### Fix

```c
if (anon_mmap_fixed( ptr, page_size, PROT_READ | PROT_WRITE, 0 ) == MAP_FAILED)
    goto error;
*(void **)ptr = __wine_syscall_dispatcher;
```

---

## Issue 3 — Medium: SIGILL and SIGBUS silently inherit `segv_handler`

**Lines**: 2877–2880
**Function**: `signal_init_process`

### Code

```c
sig_act.sa_sigaction = segv_handler;
if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
if (sigaction( SIGILL,  &sig_act, NULL ) == -1) goto error;   // sa_sigaction not updated
if (sigaction( SIGBUS,  &sig_act, NULL ) == -1) goto error;   // sa_sigaction not updated
```

### Problem

`sig_act.sa_sigaction` is set to `segv_handler` on line 2877 and is never
changed before the SIGILL and SIGBUS registrations. All three signals are
therefore dispatched through `segv_handler`. This may be intentional — all
three faults are handled via the same exception-dispatch path — but a reader
has no indication of this, and a future developer inserting a new signal
registration between lines 2878 and 2879 could inadvertently change the
SIGILL/SIGBUS handler without realising it.

### Fix

Add an explicit reassignment and comment before the SIGILL/SIGBUS calls:

```c
sig_act.sa_sigaction = segv_handler;
if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
/* SIGILL and SIGBUS are intentionally handled by the same segv_handler */
if (sigaction( SIGILL,  &sig_act, NULL ) == -1) goto error;
if (sigaction( SIGBUS,  &sig_act, NULL ) == -1) goto error;
```

Or reassign `sig_act.sa_sigaction = segv_handler` before each registration for
clarity.

---

## Issue 4 — Medium: Stack size calculation wraps on corrupted RSP

**Line**: 1606
**Function**: `setup_raise_exception`

### Code

```c
rsp &= ~(ULONG_PTR)15;
stack_size = rsp - ((rsp - sizeof(*stack) - xstate_size) & ~(ULONG_PTR)63);
stack = virtual_setup_exception( (void *)rsp, stack_size, rec );
```

### Problem

`rsp` is an unsigned `ULONG_PTR`. If the RSP value recovered from the faulting
context is corrupted or unusually small (e.g. zero, or smaller than
`sizeof(*stack) + xstate_size`), the inner subtraction wraps around to a very
large unsigned value. After the 64-byte alignment mask the result is near
`ULONG_PTR_MAX`, and `stack_size` wraps to a near-zero or nonsensical value.
`virtual_setup_exception` is then called with an incorrect size, potentially
mapping far too little exception stack space and causing a secondary fault.

This cannot happen with a valid, normally-running stack, but corrupted RSP
values are common in the very fault conditions this function is designed to
handle (stack overflow, use-after-free, etc.).

### Fix

Add a bounds check before the calculation:

```c
if (rsp < sizeof(*stack) + xstate_size + 128 /* red zone */)
{
    ERR( "RSP %#lx too small to set up exception stack\n", rsp );
    NtTerminateProcess( GetCurrentProcess(), rec->ExceptionCode );
}
stack_size = rsp - ((rsp - sizeof(*stack) - xstate_size) & ~(ULONG_PTR)63);
```

---

## Issue 5 — Low: `assert` inside signal handlers calls `abort`

**Lines**: various (e.g. in `copy_context_regs`, `save_xstate`, `restore_xstate`)
**Category**: Signal handler safety

### Code (representative)

```c
assert( xcontext->c_ex.XState.Offset == (BYTE *)xs - (BYTE *)&xcontext->c_ex );
assert( !((ULONG_PTR)dst_xs & 63) );
```

### Problem

`assert` is implemented by calling `abort()`, which raises `SIGABRT`. Calling
`abort` from within a signal handler re-enters the signal machinery with the
original handler still on the stack. `SIGABRT` is not async-signal-safe, and
the result is undefined behaviour rather than a clean crash with a useful
diagnostic.

Additionally, `abort` is not in the POSIX list of async-signal-safe functions
and may itself acquire locks, compounding any existing deadlock risk.

### Fix

Replace `assert` on signal-handler code paths with explicit checks that use
async-signal-safe output:

```c
if (xcontext->c_ex.XState.Offset != (BYTE *)xs - (BYTE *)&xcontext->c_ex)
{
    ERR( "XState offset mismatch\n" );
    return;
}
```

---

## Issue 6 — Low: `instrumentation_callback` read in signal handlers without memory barrier

**Lines**: 2285 and others (`handle_syscall_trap`, `sigsys_handler`)
**Category**: Concurrency

### Code

```c
/* in handle_syscall_trap() / sigsys_handler(): */
if (instrumentation_callback) frame->restore_flags |= RESTORE_FLAGS_INSTRUMENTATION;

/* in set_process_instrumentation_callback(): */
server_enter_uninterrupted_section( &instrumentation_callback_mutex, &sigset );
old = InterlockedExchangePointer( &instrumentation_callback, callback );
```

### Problem

`set_process_instrumentation_callback` uses a mutex and an interlocked
exchange to safely update `instrumentation_callback` between concurrent
threads. However, signal handlers cannot acquire a mutex and read the variable
with no synchronisation primitive at all.

On x86 with TSO memory ordering this is benign in practice — loads are never
reordered with respect to each other. On other architectures (ARM, AArch64)
this would be a formal data race and could produce a stale read.

The real risk is that the compiler is free to cache the value in a register
across the read, since the variable is not declared `volatile` or accessed via
an atomic intrinsic.

### Fix

Declare the variable with `volatile` (sufficient for x86):

```c
static volatile void *instrumentation_callback;
```

Or use an explicit atomic load for correctness on all platforms:

```c
if (__atomic_load_n( &instrumentation_callback, __ATOMIC_ACQUIRE ))
    frame->restore_flags |= RESTORE_FLAGS_INSTRUMENTATION;
```
