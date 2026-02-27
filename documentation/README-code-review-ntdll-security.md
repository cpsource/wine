# Code Review: dlls/ntdll/unix/security.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/security.c`

---

## Summary

Five issues were identified, all in the error-handling or defensive-validation
category.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Medium | Error handling | 918 | `NtAccessCheck` | `priv_len` underflow passes huge reply size to server |
| 2 | Low | Error handling | 913 | `NtAccessCheck` | `mapping` not validated for NULL unlike `privs`/`retlen` |
| 3 | Medium | Error handling | 842 | `NtFilterToken` | `privileges->Privileges` computed from NULL pointer (UB) |
| 4 | Low | Error handling | 78 | `NtCreateToken` | `groups_size` 32-bit overflow when `GroupCount` is large |
| 5 | Low | Error handling | 69 | `NtCreateToken` | `attr->SecurityQualityOfService` dereferences NULL when `attr` is NULL |

---

## Issue 1 — `NtAccessCheck`: `priv_len` underflow in reply-buffer size

**Line**: 918
**Function**: `NtAccessCheck`

### Code

```c
if (!privs || !retlen) return STATUS_ACCESS_VIOLATION;
priv_len = *retlen;   /* caller-supplied buffer size */
...
wine_server_set_reply( req, privs->Privilege,
    priv_len - offsetof( PRIVILEGE_SET, Privilege ) );  /* underflow if priv_len < 8 */
```

### Problem

`offsetof(PRIVILEGE_SET, Privilege)` is 8. `priv_len` is `ULONG` (unsigned).
If the caller passes `*retlen < 8` (e.g., 0 to probe the required size),
the subtraction wraps to a very large `data_size_t`. The server believes it
has a huge reply buffer and writes privilege data to `privs->Privilege`
potentially well beyond the caller's actual allocation. The
`STATUS_BUFFER_TOO_SMALL` guard at line 931 only fires after the server reply
has already been received and the overflow has occurred.

### Fix

```c
if (priv_len < offsetof( PRIVILEGE_SET, Privilege ))
{
    free( objattr );
    return STATUS_BUFFER_TOO_SMALL;
}
```

---

## Issue 2 — `NtAccessCheck`: `mapping` not validated for NULL

**Lines**: 913–916
**Function**: `NtAccessCheck`

### Code

```c
if (!privs || !retlen) return STATUS_ACCESS_VIOLATION;
/* mapping not checked */
req->mapping.read = mapping->GenericRead;   /* crash if mapping == NULL */
req->mapping.write = mapping->GenericWrite;
req->mapping.exec = mapping->GenericExecute;
req->mapping.all = mapping->GenericAll;
```

### Problem

`privs` and `retlen` are validated but the required `mapping` parameter is
not. A NULL `mapping` crashes at line 913. The fix should be consistent with
the existing check.

### Fix

```c
if (!privs || !retlen || !mapping) return STATUS_ACCESS_VIOLATION;
```

---

## Issue 3 — `NtFilterToken`: `privileges->Privileges` computed from NULL pointer

**Line**: 842
**Function**: `NtFilterToken`

### Code

```c
if (privileges)
    privileges_len = privileges->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES);
...
wine_server_add_data( req, privileges->Privileges, privileges_len );
/* ^^ privileges->Privileges computes an offset from NULL when privileges == NULL */
```

### Problem

When `privileges` is NULL, `privileges_len` is 0, but
`privileges->Privileges` is still evaluated to form the first argument.
Computing a field address from a NULL struct pointer is undefined behaviour
in C; a sufficiently aggressive optimiser may remove the preceding NULL check
or produce unexpected code. The fix is to guard the call.

### Fix

```c
if (privileges)
    wine_server_add_data( req, privileges->Privileges, privileges_len );
```

---

## Issue 4 — `NtCreateToken`: `groups_size` 32-bit overflow

**Lines**: 78, 84
**Function**: `NtCreateToken`

### Code

```c
groups_size = groups->GroupCount * sizeof( attrs[0] );   /* can overflow */

for (i = 0; i < groups->GroupCount; i++)
{
    sid = groups->Groups[i].Sid;
    groups_size += offsetof( SID, SubAuthority[sid->SubAuthorityCount] );
}
...
groups_info = malloc( groups_size );  /* too small if overflow occurred */
```

### Problem

`groups_size` is `data_size_t` (32-bit `unsigned int`). If `GroupCount` is
large (e.g., `0x40000001`), `GroupCount * 4` wraps to a small value. The
subsequent `malloc` allocates a too-small buffer, and the copy loop at lines
104–111 overflows it. Requires a privileged caller with a malformed
`TOKEN_GROUPS` structure.

### Fix

```c
if (groups->GroupCount > UINT_MAX / sizeof( attrs[0] ))
{
    free( objattr );
    return STATUS_INVALID_PARAMETER;
}
groups_size = groups->GroupCount * sizeof( attrs[0] );
```

---

## Issue 5 — `NtCreateToken`: `attr->SecurityQualityOfService` dereferences NULL when `attr` is NULL

**Line**: 69
**Function**: `NtCreateToken`

### Code

```c
if ((status = alloc_object_attributes( attr, &objattr, &objattr_size ))) return status;
/* alloc_object_attributes returns STATUS_SUCCESS for NULL attr (sync.c:216) */

if (attr->SecurityQualityOfService)   /* crash if attr == NULL */
```

### Problem

`alloc_object_attributes` handles a NULL `attr` by returning `STATUS_SUCCESS`
(sync.c line 216), so the early return at line 67 is not taken. The check at
line 69 then dereferences the NULL `attr`. Although `NtCreateToken` requires
a non-NULL `attr` in normal use, the code should be consistent with how the
rest of the function would behave if `attr` were absent.

### Fix

```c
if (attr && attr->SecurityQualityOfService)
```
