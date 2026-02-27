# Code Review: dlls/ntdll/unix/signal_arm64.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/signal_arm64.c`

---

## Summary

One issue was identified. The automated Explore agent proposed four findings;
three were rejected as false positives after manual verification:

- *`NtSetContextThread` missing XState.Offset validation* — ARM64's
  `NtSetContextThread` has no `CONTEXT_XSTATE` code path at all (lines
  373–399 handle only INTEGER, CONTROL, FLOATING_POINT, ARM64_X18, and
  DEBUG_REGISTERS). No XState pointer arithmetic is performed, so there is
  nothing to validate. The analogous bug in `signal_i386.c` existed because
  i386 has a dedicated `CONTEXT_XSTATE` block.
- *`NtGetContextThread` missing XState.Offset validation* — same reason;
  the ARM64 implementation (lines 419–441) has no CONTEXT_XSTATE path.
- *`context_init_empty_xstate` All.Length overflow* — `xstate_buffer` is
  always an internally-supplied trusted pointer placed above `xctx` in the
  same stack frame, making `XState.Offset` always positive. Same pattern as
  `context_init_xstate` in `signal_i386.c`, which was verified non-buggy.

| # | Severity | Category | Line | Short description |
|---|----------|----------|------|-------------------|
| 1 | Low | Error handling | 969 | `KeUserModeCallback`: user SP underflow when `len` is very large |

---

## Issue 1 — Low: `KeUserModeCallback` integer underflow in SP calculation

**Line**: 969
**Function**: `KeUserModeCallback`

### Code

```c
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    //            ^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //            user-mode   grows with len; if > frame->sp, unsigned underflow
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;   /* validates KERNEL stack only — not sp above */

    ...
    memcpy( stack->args_data, args, len );  /* writes through potentially-bogus sp */
```

### Problem

`offsetof(struct callback_stack_layout, args_data[len])` grows with `len`.
If this value plus 16 exceeds `frame->sp` (the user-mode stack pointer), the
`ULONG64` subtraction wraps around to a very large value, and `sp` points to
an invalid address.

The stack-overflow guard at line 972 validates the **kernel** stack depth, not
the user-mode `sp` calculation. The `memcpy` at line 981 then writes through
the wrapped pointer, causing a write to invalid user-mode memory.

This is the same latent bug fixed in `signal_i386.c` (line 1752) and
`signal_arm.c` (line 739).

### Fix

```c
    size_t layout_size = offsetof( struct callback_stack_layout, args_data[len] ) + 16;
    ULONG64 sp;
    struct callback_stack_layout *stack;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;
    if (layout_size > frame->sp)
        return STATUS_STACK_OVERFLOW;
    sp = (frame->sp - layout_size) & ~15;
    stack = (struct callback_stack_layout *)sp;
```
