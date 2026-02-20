# Code Review: dlls/ntdll/unix/registry.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/registry.c`

---

## Summary

One issue was identified. The automated Explore agent proposed five findings;
four were rejected as false positives after manual verification:

- *`NtLoadKeyEx` uninitialized-pointer free* — `get_nt_and_unix_names` always
  initialises both output parameters to NULL (file.c lines 4365–4366) before
  taking any other action; `free(NULL)` is safe and the function comment
  "must be freed by caller in all cases" is consistent with that.
- *`NtCreateKey` NULL `ObjectName` dereference* — NULL `ObjectName` is not a
  valid input for any registry operation. `alloc_object_attributes` (called
  immediately after, sync.c line 249) already guards `attr->ObjectName` with
  `if (attr->ObjectName)`. Windows itself faults on NULL `ObjectName` in
  registry APIs; Wine's behaviour matches.
- *`NtOpenKeyEx` NULL `ObjectName` dereference* — same reasoning as above.
- *`open_hkcu_key` snprintf chain buffer overflow* — the longest `path` Wine
  ever passes is `"Software\\Wine\\DllOverrides"` (28 chars). Worst-case total
  with a maximal SID (15 SubAuthorities at `0xFFFFFFFF`): 32 + 165 + 30 = 227
  chars, within the 256-byte buffer. Cannot overflow with real inputs.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Low | Error handling | 852 | `NtQueryLicenseValue` | `DWORD` overflow in `info_length`; garbage written to `*type`/`*retlen` |

---

## Issue 1 — `NtQueryLicenseValue`: integer overflow in `info_length`

**Line**: 852
**Function**: `NtQueryLicenseValue`

### Code

```c
DWORD info_length, count;
...
info_length = FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data ) + length;
if (!(info = malloc( info_length ))) return STATUS_NO_MEMORY;
...
status = NtQueryValueKey( key, name, KeyValuePartialInformation,
                          info, info_length, &count );
if (!status || status == STATUS_BUFFER_OVERFLOW)
{
    if (type) *type = info->Type;        /* reads unwritten allocation if overflow */
    *retlen = info->DataLength;          /* reads unwritten allocation if overflow */
    if (status == STATUS_BUFFER_OVERFLOW)
        status = STATUS_BUFFER_TOO_SMALL;
    else
        memcpy( data, info->Data, info->DataLength );
}
```

### Problem

`info_length` is a `DWORD` (32-bit unsigned). `FIELD_OFFSET(..., Data)` is 12.
If `length` ≥ `0xFFFFFFF4` the addition wraps around, making `info_length`
≤ 11 — smaller than the `KEY_VALUE_PARTIAL_INFORMATION` header (12 bytes).

`malloc` then allocates a sub-header-sized buffer. `NtQueryValueKey` receives
this small `info_length` as its buffer-size argument and returns
`STATUS_BUFFER_OVERFLOW` without writing any data. The code then reads
`info->Type` (offset 4) and `info->DataLength` (offset 8) from the
uninitialized allocation and stores them in the caller's `*type` and `*retlen`
output variables. The function returns `STATUS_BUFFER_TOO_SMALL`, but the
output variables contain garbage values.

Requires a pathological `length` value (near `ULONG_MAX`), so low risk in
practice.

### Fix

```c
if (length > ULONG_MAX - FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data ))
    return STATUS_INVALID_PARAMETER;
info_length = FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data ) + length;
if (!(info = malloc( info_length ))) return STATUS_NO_MEMORY;
```
