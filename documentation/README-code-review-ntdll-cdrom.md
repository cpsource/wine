# Code Review: dlls/ntdll/unix/cdrom.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/cdrom.c`

---

## Summary

Five issues were identified ranging from a high-severity functional bug to low-severity
code quality concerns.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | High | Bug | 1506 | `PBYTE *bp` wrong type breaks multi-sector raw reads |
| 2 | Medium | Bug | 722 | `CDROM_GetControl` always returns `STATUS_NOT_SUPPORTED` |
| 3 | Medium | Security | ~1777, ~1998 | Integer overflow in SCSI passthrough allocation sizes |
| 4 | Low | Cleanup | 301–334 | Dead `#if 0` code block |
| 5 | Low | Style | 698–702 | `CDROM_GetStatusCode` ignores its parameter |

---

## Issue 1 — High: Wrong pointer type for `bp` corrupts multi-sector raw reads

**Line**: 1506
**Function**: `CDROM_RawRead`

### Code

```c
PBYTE *bp; /* current buffer pointer */
...
for (i = 0, bp = buffer; i < raw->SectorCount;
     i++, lba++, bp += 2352)
{
    msf = (struct cdrom_msf*)bp;
    msf->cdmsf_min0   = lba / CD_FRAMES / CD_SECS;
    ...
    io = ioctl(fd, CDROMREADRAW, msf);
```

### Problem

`PBYTE` is `BYTE *`, so `PBYTE *bp` is `BYTE **` — a pointer-to-pointer.
Pointer arithmetic on `BYTE **` advances by `2352 * sizeof(BYTE *)` per step.
On a 64-bit system that is **18,816 bytes per iteration** instead of 2,352.

- **First sector (i = 0)**: correct — `bp = buffer`, offset 0.
- **Every subsequent sector**: `msf` points far past the end of `buffer`,
  causing out-of-bounds writes and reads.

Multi-sector raw reads (`SectorCount > 1`) have never worked correctly on
64-bit Linux because of this type error.

### Fix

```c
- PBYTE *bp; /* current buffer pointer */
+ PBYTE  bp; /* current buffer pointer */
```

---

## Issue 2 — Medium: `CDROM_GetControl` always returns `STATUS_NOT_SUPPORTED`

**Line**: 722
**Function**: `CDROM_GetControl`

### Code

```c
static NTSTATUS CDROM_GetControl(int dev, int fd, CDROM_AUDIO_CONTROL* cac)
{
#ifdef __APPLE__
    uint16_t speed;
    int io = ioctl( fd, DKIOCCDGETSPEED, &speed );
    if (io != 0) return CDROM_GetStatusCode( io );
    cac->LogicalBlocksPerSecond = speed/2;
#else
    cac->LogicalBlocksPerSecond = 1; /* FIXME */
#endif
    cac->LbaFormat = 0; /* FIXME */
    return STATUS_NOT_SUPPORTED;   // <-- always reached
}
```

### Problem

On macOS the ioctl succeeds and `cac` is populated with a real value, but the
function still returns `STATUS_NOT_SUPPORTED`, signalling failure to the caller.
Any caller that gates on the return value will discard valid data.

On non-Apple platforms the struct is filled with stub values and failure is
returned, which is at least internally consistent (if misleading to callers
that check the status before using the output).

### Fix

Return `STATUS_SUCCESS` at the end of the Apple path:

```c
#ifdef __APPLE__
    uint16_t speed;
    int io = ioctl( fd, DKIOCCDGETSPEED, &speed );
    if (io != 0) return CDROM_GetStatusCode( io );
    cac->LogicalBlocksPerSecond = speed/2;
    cac->LbaFormat = 0;
    return STATUS_SUCCESS;
#else
    cac->LogicalBlocksPerSecond = 1; /* FIXME */
    cac->LbaFormat = 0; /* FIXME */
    return STATUS_NOT_SUPPORTED;
#endif
```

---

## Issue 3 — Medium: Integer overflow in SCSI passthrough allocation sizes

**Lines**: ~1777, ~1998
**Functions**: 32-bit SCSI passthrough thunks

### Code (representative)

```c
pkt = calloc(1, sizeof(SCSI_PASS_THROUGH_DIRECT) + in_pkt32->SenseInfoLength);
```

and

```c
pkt = calloc(1, sizeof(SCSI_PASS_THROUGH) + in_pkt32->SenseInfoLength
                                           + in_pkt32->DataTransferLength);
```

### Problem

`SenseInfoLength` and `DataTransferLength` come from a 32-bit user structure.
If either is large (or both together), the addition can silently wrap on
`size_t`, causing `calloc` to allocate a much smaller buffer than expected and
subsequent writes to overflow it.

### Fix

Validate the fields before computing the allocation size, e.g.:

```c
if (in_pkt32->SenseInfoLength > SENSEBUFLEN)
    return STATUS_INVALID_PARAMETER;
size_t alloc = sizeof(SCSI_PASS_THROUGH_DIRECT) + in_pkt32->SenseInfoLength;
if (alloc < sizeof(SCSI_PASS_THROUGH_DIRECT))
    return STATUS_NO_MEMORY;
pkt = calloc(1, alloc);
```

---

## Issue 4 — Low: Dead code should be removed

**Lines**: 301–334

### Code

```c
/* Proposed media change function: not really needed at this time */
/* This is a 1 or 0 type of function */
#if 0
static int CDROM_MediaChanged(int dev)
{
    ...
}
#endif
```

### Problem

The function has been disabled with `#if 0` and is not compiled or referenced.
The accompanying comment suggests it was experimental. Dead code adds noise and
can mislead readers into thinking the logic is in use.

### Fix

Remove the block. The code is preserved in git history if ever needed.

---

## Issue 5 — Low: `CDROM_GetStatusCode` ignores its parameter

**Lines**: 698–702
**Function**: `CDROM_GetStatusCode`

### Code

```c
static NTSTATUS CDROM_GetStatusCode(int io)
{
    if (io == 0) return STATUS_SUCCESS;
    return errno_to_status( errno );   // `io` not used on this path
}
```

### Problem

The parameter `io` carries the raw `ioctl()` return value but is only inspected
for the zero/non-zero distinction. The actual error information is always taken
from the global `errno`. The signature implies `io` encodes an error code,
which is misleading.

This is technically correct for `ioctl()` (which sets `errno` on `-1` return
and the return value itself is not an error code), but:

- Callers are not warned that passing any non-zero value (including positive
  values from ioctls that return data) will silently fall through to
  `errno_to_status`.
- The stale `errno` from a previous call could be picked up if an ioctl
  returns a non-zero success value.

### Suggestion

Add a comment to the function clarifying the contract, or narrow the signature
to only accept `-1` / `0` rather than an arbitrary `int`.

---

## Notes

- Several `/* FIXME */` markers exist throughout the file indicating known
  incomplete implementations (e.g. `CDROM_GetDeviceNumber` returning hardcoded
  values at ~line 731). These are pre-existing and out of scope for this review
  but should be tracked as separate work items.
- Error handling style is inconsistent — some functions use `goto end` cleanup
  labels, others return directly. This is a pre-existing style issue and not a
  correctness concern.
