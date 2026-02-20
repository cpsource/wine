# Code Review: dlls/ntdll/unix/signal_i386.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/signal_i386.c`

---

## Summary

Three issues were identified. All share the theme of missing input validation on
caller-supplied context structures in two public NT APIs.

The automated Explore agent proposed six findings; three were rejected as false
positives after manual verification:

- *ATL thunk type 3 EIP calculation* — `func` is an absolute immediate operand
  of `movl func, ecx` + `jmp ecx`, not a relative displacement. Setting
  `EIP = func` directly is correct, unlike types 1/2 which use `jmp rel32`.
- *`context_init_xstate` signed/unsigned arithmetic* — `xstate_buffer` is
  always at a higher address than `xctx` in every call site, so `XState.Offset`
  is always positive.
- *TRACE/ERR in signal handlers* — Wine deliberately uses its own debug channel
  in signal handlers; this is an accepted design trade-off.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Medium | Input validation | 951, 1033 | `NtSetContextThread`: `XState.Offset` not validated before computing xs; OOB reads |
| 2 | Medium | Input validation | 1154 | `NtGetContextThread`: `XState.Offset` not validated before computing xstate; OOB read/write |
| 3 | Low | Error handling | 1752 | `KeUserModeCallback`: user-ESP underflow when `len` is very large |

---

## Issue 1 — Medium: `NtSetContextThread` uses `XState.Offset` without bounds check

**Lines**: 948–958, 1030–1039
**Function**: `NtSetContextThread`

### Code

```c
/* First block — initial validation (lines 948–958) */
if ((flags & CONTEXT_XSTATE) && xstate_extended_features)
{
    CONTEXT_EX *context_ex = (CONTEXT_EX *)(context + 1);
    XSAVE_AREA_HEADER *xs = (XSAVE_AREA_HEADER *)((char *)context_ex + context_ex->XState.Offset);
    //                                                                    ^^^^^^^^^^^^^^^^^^^^^^^^
    //                                                             Offset is LONG (signed); never checked

    if (context_ex->XState.Length < sizeof(XSAVE_AREA_HEADER) ||
        context_ex->XState.Length > xstate_size)
        return STATUS_INVALID_PARAMETER;          /* Length checked; Offset is NOT */

    if ((xs->Mask & xstate_extended_features)    /* OOB read if Offset < 0 */
        && (...)) return STATUS_BUFFER_OVERFLOW;
}

/* Second block — actual XSTATE copy (lines 1030–1039) */
if (flags & CONTEXT_XSTATE)
{
    CONTEXT_EX *context_ex = (CONTEXT_EX *)(context + 1);
    XSAVE_AREA_HEADER *xs = (XSAVE_AREA_HEADER *)((char *)context_ex + context_ex->XState.Offset);
    //                                                                    same unvalidated Offset
    copy_xstate( &frame->xstate, xs, xs->Mask );  /* OOB read from xs */
    if (xs->CompactionMask) frame->xstate.Mask |= ...;  /* OOB read */
}
```

### Problem

`context_ex->XState.Offset` is of type `LONG` (signed 32-bit). A caller can
supply a negative value, causing the `xs` pointer to be computed as:

```
xs = (char *)context_ex + (negative_signed_LONG)
   = address before context_ex  →  before the CONTEXT structure
```

The validation block at lines 953–954 checks `XState.Length` but never checks
`XState.Offset`. The `xs` pointer is already computed at line 951 and used at
lines 956–957 to read `xs->Mask` and `xs->CompactionMask` — both out of bounds.

The second XSTATE-copy block at lines 1032–1039 repeats the same computation
(line 1033) and passes the out-of-bounds `xs` to `copy_xstate`, which reads
additional fields from it.

Both blocks are only active when `xstate_extended_features != 0`; the else-
branch at line 960 (`flags &= ~CONTEXT_XSTATE`) prevents the second block from
running when extended features are absent.

### Impact

An in-process caller (any Win32 application) that calls `NtSetContextThread`
with a crafted `CONTEXT_EX.XState.Offset` can cause reads from arbitrary
addresses relative to the CONTEXT buffer, with behaviour ranging from a
segfault to silent mis-read of heap/stack data.

### Fix

Add an explicit Offset lower-bound check before computing `xs` in both blocks:

```c
if (context_ex->XState.Offset < (LONG)sizeof(CONTEXT_EX) ||
    context_ex->XState.Length < sizeof(XSAVE_AREA_HEADER) ||
    context_ex->XState.Length > xstate_size)
    return STATUS_INVALID_PARAMETER;
XSAVE_AREA_HEADER *xs = (XSAVE_AREA_HEADER *)((char *)context_ex + context_ex->XState.Offset);
```

Apply the same guard to the second block at line 1032.

---

## Issue 2 — Medium: `NtGetContextThread` uses `XState.Offset` without bounds check; OOB write

**Lines**: 1151–1175
**Function**: `NtGetContextThread`

### Code

```c
if ((needed_flags & CONTEXT_XSTATE) && xstate_extended_features)
{
    CONTEXT_EX *context_ex = (CONTEXT_EX *)(context + 1);
    XSAVE_AREA_HEADER *xstate = (XSAVE_AREA_HEADER *)((char *)context_ex + context_ex->XState.Offset);
    //                                                                        ^^^^^^^^^^^^^^^^^^^^^^^^
    //                                                                        Offset not validated

    if (context_ex->XState.Length < sizeof(XSAVE_AREA_HEADER) ||
        context_ex->XState.Length > xstate_size)
        return STATUS_INVALID_PARAMETER;           /* Length checked; Offset is NOT */

    if (user_shared_data->XState.CompactionEnabled)
    {
        mask = xstate->CompactionMask & xstate_extended_features;   /* OOB read */
        xstate->Mask = frame->xstate.Mask & mask;                   /* OOB WRITE */
        xstate->CompactionMask = 0x8000000000000000 | mask;         /* OOB WRITE */
    }
    else
    {
        mask = xstate->Mask & xstate_extended_features;             /* OOB read */
        xstate->Mask = frame->xstate.Mask & mask;                   /* OOB WRITE */
        xstate->CompactionMask = 0;                                  /* OOB WRITE */
    }
}
```

### Problem

Identical to Issue 1: `context_ex->XState.Offset` is `LONG` (signed) and is not
validated before computing `xstate`. The validation at lines 1157–1159 only
checks `XState.Length`.

This path is more severe than Issue 1 because the XSAVE_AREA_HEADER pointed to
by `xstate` is **written** (lines 1165–1166 and 1171–1172). With a negative
`XState.Offset`, those writes corrupt memory before the caller's CONTEXT buffer
— a controlled out-of-bounds write reachable from any Win32 application.

### Fix

Same as Issue 1: validate Offset before computing xstate:

```c
if (context_ex->XState.Offset < (LONG)sizeof(CONTEXT_EX) ||
    context_ex->XState.Length < sizeof(XSAVE_AREA_HEADER) ||
    context_ex->XState.Length > xstate_size)
    return STATUS_INVALID_PARAMETER;
XSAVE_AREA_HEADER *xstate = (XSAVE_AREA_HEADER *)((char *)context_ex + context_ex->XState.Offset);
```

---

## Issue 3 — Low: `KeUserModeCallback` integer underflow when `len` is very large

**Line**: 1752
**Function**: `KeUserModeCallback`

### Code

```c
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG esp = (frame->esp - offsetof(struct callback_stack_layout, args_data[len])) & ~3;
    //          ^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //          user-mode    may exceed frame->esp if len is huge → unsigned wrap
    struct callback_stack_layout *stack = (struct callback_stack_layout *)esp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;    /* checks KERNEL stack only — not esp above */

    ...
    memcpy( stack->args_data, args, len );   /* writes through potentially-bogus esp */
```

### Problem

`offsetof(struct callback_stack_layout, args_data[len])` grows with `len`.
If this value exceeds `frame->esp` (the user-mode stack pointer), the `ULONG`
subtraction wraps around, producing a very large bogus `esp`.

The stack-overflow check at line 1755 validates the **kernel** stack depth, not
the user-mode `esp` calculation. The `memcpy` at line 1763 then writes through
the wrapped pointer, causing a write to an invalid user-mode address.

`KeUserModeCallback` is called from Wine's own internal kernel emulation code,
so `len` is trusted in practice — this is a latent correctness bug rather than a
direct security vulnerability. However, an unexpected large `len` would produce
a confusing crash rather than a clean `STATUS_STACK_OVERFLOW`.

### Fix

```c
size_t layout_size = offsetof( struct callback_stack_layout, args_data[len] );
if (layout_size > frame->esp)
    return STATUS_STACK_OVERFLOW;
ULONG esp = (frame->esp - layout_size) & ~3;
```
