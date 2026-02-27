# Code Review: dlls/ntdll/unix/signal_arm.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/signal_arm.c`

---

## Summary

One issue was identified. The automated Explore agent proposed four findings;
three were rejected as false positives after manual verification:

- *Missing `NumberParameters` for `EXCEPTION_DATATYPE_MISALIGNMENT`* —
  this exception takes zero parameters by the Windows specification;
  `NumberParameters = 0` from the `{ 0 }` initialiser is correct.
- *Missing `NumberParameters` for `EXCEPTION_ILLEGAL_INSTRUCTION`* — same;
  this exception requires no extra information.
- *Missing `NumberParameters` for `EXCEPTION_SINGLE_STEP`* — same; only
  `EXCEPTION_BREAKPOINT` requires `NumberParameters = 1` (to carry the
  breakpoint type code); `EXCEPTION_SINGLE_STEP` does not.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Low | Error handling | 739 | `KeUserModeCallback`: user SP underflow when `len` is very large |

---

## Issue 1 — Low: `KeUserModeCallback` integer underflow in SP calculation

**Line**: 739
**Function**: `KeUserModeCallback`

### Code

```c
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 8) & ~7;
    //          ^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //          user-mode   layout_size grows with len; if > frame->sp, unsigned wrap-around
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;   /* checks KERNEL stack depth only — not sp above */

    ...
    memcpy( stack->args_data, args, len );  /* writes through potentially-bogus sp */
```

### Problem

`offsetof(struct callback_stack_layout, args_data[len])` grows linearly with
`len`. If this value plus 8 exceeds `frame->sp` (the user-mode stack pointer),
the `ULONG` subtraction wraps around to a very large value, and `sp` points to
an invalid address.

The stack-overflow guard at line 742 validates the **kernel** stack depth (via
`&frame`), not the user-mode `sp` calculation. The `memcpy` at line 751 then
writes `len` bytes through the wrapped `sp`, causing a write to invalid
user-mode memory.

This is the same latent bug fixed in `signal_i386.c` (`KeUserModeCallback`,
line 1752 there). `KeUserModeCallback` is called from trusted internal Wine
code, so `len` is controlled in practice — the risk is a confusing crash rather
than a security vulnerability.

### Fix

```c
    size_t layout_size = offsetof( struct callback_stack_layout, args_data[len] ) + 8;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;
    if (layout_size > frame->sp)
        return STATUS_STACK_OVERFLOW;
    ULONG sp = (frame->sp - layout_size) & ~7;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;
```
