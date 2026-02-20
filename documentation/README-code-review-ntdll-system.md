# Code Review: dlls/ntdll/unix/system.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/system.c`

---

## Summary

Two issues were identified. A third candidate was rejected as a false positive
after manual verification:

- *`strcpy` without bounds in `get_system_serial`/`get_chassis_serial`* —
  both functions are `static` with a single call site (`create_smbios_data`,
  line 2206/2214) that always passes a 128-byte buffer via the `S()` macro.
  The longest fallback string ("Chassis Serial Number") is 21 bytes, well
  within 128. No actual overflow is possible with the current callers.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Medium | Error handling | 3794 | `NtQuerySystemInformation` | `malloc(buffer)` unchecked; NULL passed to `wine_server_set_reply` |
| 2 | Medium | Error handling | 1578 | `init_logical_proc_info` | Two `realloc` calls unchecked; leaks buffers on failure |

---

## Issue 1 — `NtQuerySystemInformation` (`SystemProcessIdInformation`): unchecked `malloc`

**Lines**: 3794–3813
**Function**: `NtQuerySystemInformation` (case `SystemProcessIdInformation`)

### Code

```c
buffer = malloc( str->MaximumLength );
SERVER_START_REQ( get_process_image_name )
{
    req->pid = id->ProcessId;
    wine_server_set_reply( req, buffer, str->MaximumLength );  /* NULL if malloc failed */
    ret = wine_server_call( req );
    name_len = reply->len;
}
SERVER_END_REQ;
...
free( buffer );
```

### Problem

`malloc` return is not checked. If it returns NULL (possible when
`MaximumLength` is large and memory is scarce), NULL is passed to
`wine_server_set_reply`. The server then attempts to write the image-name
reply data to address 0, corrupting memory or crashing.

### Fix

```c
if (!(buffer = malloc( str->MaximumLength ))) return STATUS_NO_MEMORY;
SERVER_START_REQ( get_process_image_name )
{
```

---

## Issue 2 — `init_logical_proc_info`: two `realloc` calls not checked

**Lines**: 1578–1581
**Function**: `init_logical_proc_info`

### Code

```c
logical_proc_info = realloc( logical_proc_info,
    logical_proc_info_len * sizeof(*logical_proc_info) );
logical_proc_info_alloc_len = logical_proc_info_len;

logical_proc_info_ex = realloc( logical_proc_info_ex,
    logical_proc_info_ex_size );
logical_proc_info_ex_alloc_size = logical_proc_info_ex_size;
```

### Problem

Both `realloc` results are assigned back to the original pointers without
checking for NULL. On failure the previous allocation is silently leaked
(the pointer is overwritten with NULL before it can be freed), and the
`_alloc_len`/`_alloc_size` counters are set to the new (larger) sizes
despite the allocation failing. Subsequent accesses through the now-NULL
pointers crash.

These are shrink reallocations (trimming excess capacity after
`create_logical_proc_info` finishes), so failure is uncommon in practice but
still possible.

### Fix

```c
SYSTEM_LOGICAL_PROCESSOR_INFORMATION *tmp_info;
SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *tmp_info_ex;

tmp_info = realloc( logical_proc_info,
    logical_proc_info_len * sizeof(*logical_proc_info) );
if (tmp_info)
{
    logical_proc_info = tmp_info;
    logical_proc_info_alloc_len = logical_proc_info_len;
}

tmp_info_ex = realloc( logical_proc_info_ex, logical_proc_info_ex_size );
if (tmp_info_ex)
{
    logical_proc_info_ex = tmp_info_ex;
    logical_proc_info_ex_alloc_size = logical_proc_info_ex_size;
}
```

On failure the existing (slightly oversized) buffers are kept, which is
correct.
