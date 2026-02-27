# Code Review: dlls/ntdll/unix/virtual.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/virtual.c`

---

## Summary

Five issues were identified ranging from a high-severity out-of-bounds write to
low-severity input validation gaps.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | High | Buffer overflow | 2858–2875 | OOB write in ARM64X relocation processing |
| 2 | Medium | Error handling | 2418 | `pread` return value unchecked; short reads silently ignored |
| 3 | Medium | Integer overflow | 214 | `ROUND_SIZE` macro overflows for sizes near `SIZE_MAX` |
| 4 | Medium | Memory management | 1265–1273 | Partial `pages_vprot` allocation not freed on failure |
| 5 | Low | Input validation | 2853 | `reloc->SizeOfBlock` not validated against `reloc_end` |

---

## Issue 1 — High: OOB write in `apply_arm64x_relocations`

**Lines**: 2858–2875
**Function**: `apply_arm64x_relocations`

### Code

```c
USHORT offset = *rel & 0xfff;      /* 0..4095 */
USHORT type   = (*rel >> 12) & 3;
USHORT arg    = *rel >> 14;        /* 0..3    */
// ...
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
    memset( page + offset, 0, 1 << arg );        /* writes 1/2/4/8 bytes */
    break;
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
    memcpy( page + offset, rel, 1 << arg );       /* writes 1/2/4/8 bytes */
    break;
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
    *(int *)(page + offset) += val;               /* always writes 4 bytes */
    break;
```

### Problem

`offset` is 12 bits wide (values 0–4095) and `page` points to a region of
exactly one page (4096 bytes). The three write operations do not check that
`offset + write_size <= page_size` before accessing memory:

- `ZEROFILL` / `VALUE`: `arg = 3` → 8 bytes written; any `offset > 4088`
  writes 1–7 bytes past the end of the page.
- `DELTA`: 4 bytes written; any `offset > 4092` writes 1–3 bytes past the
  end of the page.

A crafted or malformed ARM64X PE binary can trigger out-of-bounds writes of up
to 7 bytes per relocation entry. No existing bounds check guards any of the
three write paths.

This is exploitable from a malicious PE file loaded into the Wine process.

### Fix

Add a bounds check before each write:

```c
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
    if (offset + (1 << arg) > page_size) break;
    memset( page + offset, 0, 1 << arg );
    break;
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
    if (offset + (1 << arg) > page_size) break;
    memcpy( page + offset, rel, 1 << arg );
    rel += (1 << arg) / sizeof(USHORT);
    break;
case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
    if (offset + sizeof(int) > page_size) break;
    *(int *)(page + offset) += val;
    break;
```

---

## Issue 2 — Medium: `pread` return value unchecked

**Line**: 2418
**Function**: `map_file_into_view` (fallback path)

### Code

```c
/* fallback when mmap() fails due to non-page-aligned file offset */
mprotect( map_addr, map_size, PROT_READ | PROT_WRITE );
pread( fd, map_addr, size, offset );   /* return value discarded */
return STATUS_SUCCESS;
```

### Problem

This path is taken when `mmap` fails due to a non-page-aligned file offset
(e.g., on filesystems that do not support `mmap` with arbitrary offsets). The
`pread` call reads file data directly into the mapped region as a fallback.

`pread` can legitimately return less than `size` bytes — due to a signal
interruption, reaching EOF early, or a transient I/O error. The function
discards the return value and unconditionally returns `STATUS_SUCCESS`, leaving
the remainder of the mapped region with whatever contents `mmap` placed there
(typically zeros, but not guaranteed). The caller has no indication that the
mapping is incomplete.

### Fix

Loop until all bytes are read, or return an error:

```c
ssize_t nread = 0, ret;
while (nread < (ssize_t)size)
{
    ret = pread( fd, (char *)map_addr + nread, size - nread, offset + nread );
    if (ret <= 0)
    {
        ERR( "pread error %s, range %p-%p\n", strerror(errno), map_addr,
             (char *)map_addr + size );
        return STATUS_UNEXPECTED_IO_ERROR;
    }
    nread += ret;
}
```

---

## Issue 3 — Medium: `ROUND_SIZE` macro overflows for large user-supplied sizes

**Line**: 214

### Code

```c
#define ROUND_SIZE(addr,size,mask) \
    (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))
```

### Problem

If `size` is close to `SIZE_MAX` and `addr` has non-zero low bits, the
addition `size + (addr & mask) + mask` wraps around to a small unsigned value.
The result is then smaller than the original `size`, causing any subsequent
allocation or mapping operation to reserve far less memory than requested.

The macro is used throughout the file with values that originate from
`NtAllocateVirtualMemory` and `NtMapViewOfSection` parameters — i.e., directly
from user-space callers. An application (or a compromised caller) can supply a
crafted `size` and `addr` combination that produces an arbitrarily small
rounded result, leading to under-allocation followed by out-of-bounds writes
in the caller.

### Fix

Validate the inputs before rounding, or check the result after:

```c
/* At each call site that accepts user-supplied sizes: */
if (size > SIZE_MAX - (UINT_PTR)addr - granularity_mask)
    return STATUS_INVALID_PARAMETER;
```

Or add a checking wrapper:

```c
static inline SIZE_T round_size_checked( UINT_PTR addr, SIZE_T size, UINT_PTR mask,
                                         NTSTATUS *status )
{
    SIZE_T rounded = ROUND_SIZE( addr, size, mask );
    if (rounded < size) { *status = STATUS_INVALID_PARAMETER; return 0; }
    return rounded;
}
```

---

## Issue 4 — Medium: Partial `pages_vprot` allocation not freed on failure

**Lines**: 1265–1273
**Function**: `alloc_pages_vprot`

### Code

```c
for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
{
    if (pages_vprot[i]) continue;
    if ((ptr = anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE )) == MAP_FAILED)
    {
        ERR( "anon mmap error %s for vprot table, size %08lx\n",
             strerror(errno), pages_vprot_mask + 1 );
        return FALSE;
    }
    pages_vprot[i] = ptr;
}
```

### Problem

If `anon_mmap_alloc` fails for entry `i`, all entries allocated earlier in
this loop iteration (indices `idx >> pages_vprot_shift` through `i - 1`) have
been committed and stored in `pages_vprot`. The function returns `FALSE` to
signal failure, but those pages remain mapped and are never freed.

On a system under memory pressure — the exact condition that caused
`anon_mmap_alloc` to fail — these leaked anonymous mappings are permanent for
the process lifetime and make subsequent retries even harder. If the calling
operation is aborted entirely, the allocated sub-tables are wasted.

### Fix

Track the first index allocated in this call and free newly-added entries on
failure:

```c
size_t first = SIZE_MAX;
for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
{
    if (pages_vprot[i]) continue;
    if ((ptr = anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE )) == MAP_FAILED)
    {
        ERR( "anon mmap error %s for vprot table, size %08lx\n",
             strerror(errno), pages_vprot_mask + 1 );
        /* free entries allocated in this call */
        for (; first < i; first++)
        {
            if (pages_vprot[first])
            {
                munmap( pages_vprot[first], pages_vprot_mask + 1 );
                pages_vprot[first] = NULL;
            }
        }
        return FALSE;
    }
    if (first == SIZE_MAX) first = i;
    pages_vprot[i] = ptr;
}
```

---

## Issue 5 — Low: `reloc->SizeOfBlock` not validated against buffer end

**Line**: 2853
**Function**: `apply_arm64x_relocations`

### Code

```c
const USHORT *rel     = (const USHORT *)(reloc + 1);
const USHORT *rel_end = (const USHORT *)reloc + reloc->SizeOfBlock / sizeof(USHORT);
// ...
while (rel < rel_end && *rel) { ... }
```

### Problem

`rel_end` is computed purely from `reloc->SizeOfBlock`, a field read from the
PE binary, without checking that `rel_end <= (const USHORT *)reloc_end` (the
validated end of the entire relocation directory). If `SizeOfBlock` is set to
a value larger than the actual block, the inner loop reads past the end of the
relocation data buffer.

The outer loop checks `reloc < reloc_end - 1` but this only guards the block
header, not the extent of the entry array within the block.

### Fix

Clamp `rel_end` to the overall relocation buffer boundary:

```c
const USHORT *rel_end = min(
    (const USHORT *)reloc + reloc->SizeOfBlock / sizeof(USHORT),
    (const USHORT *)reloc_end );
```
