# Code Review: dlls/ntdll/unix/loadorder.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/loadorder.c`

---

## Summary

Three issues were identified, all unchecked allocation return values.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Medium | Error handling | 181 | `add_load_order` | `realloc(env_list.order)` unchecked; leaks list, crashes on write |
| 2 | Medium | Error handling | 233 | `init_load_order` | `malloc(order)` unchecked; immediate NULL dereference |
| 3 | Medium | Error handling | 288 | `open_app_key` | `malloc(nameW.Buffer)` unchecked; immediate NULL dereference |

---

## Issue 1 — `add_load_order`: `realloc` return not checked

**Lines**: 177–185
**Function**: `add_load_order`

### Code

```c
if (i >= env_list.alloc)
{
    env_list.alloc += LOADORDER_ALLOC_CLUSTER;
    env_list.order = realloc( env_list.order, env_list.alloc * sizeof(*lo) );
}
env_list.order[i].loadorder  = lo->loadorder;   /* crash if NULL */
env_list.order[i].modulename = lo->modulename;
env_list.count++;
```

### Problem

`realloc` result is assigned directly back to `env_list.order`. On failure the
original list is leaked, `env_list.order` becomes NULL, and the two stores at
lines 183–184 immediately dereference it.

### Fix

```c
struct module_loadorder *tmp = realloc( env_list.order, env_list.alloc * sizeof(*lo) );
if (!tmp) return;
env_list.order = tmp;
```

---

## Issue 2 — `init_load_order`: `malloc(order)` not checked

**Lines**: 233–234
**Function**: `init_load_order`

### Code

```c
order = entry = malloc( (strlen(overrides) + 1) * sizeof(WCHAR) );
ntdll_umbstowcs( overrides, strlen(overrides) + 1, order, strlen(overrides) + 1 );
```

### Problem

`malloc` return is not checked. If it fails, `order` is NULL and
`ntdll_umbstowcs` writes to NULL on the next line.

### Fix

```c
order = entry = malloc( (strlen(overrides) + 1) * sizeof(WCHAR) );
if (!order) return;
ntdll_umbstowcs( overrides, strlen(overrides) + 1, order, strlen(overrides) + 1 );
```

---

## Issue 3 — `open_app_key`: `malloc(nameW.Buffer)` not checked

**Lines**: 288–290
**Function**: `open_app_key`

### Code

```c
nameW.Buffer = malloc( len * sizeof(WCHAR) );
wcscpy( nameW.Buffer, app_name );       /* crash if NULL */
wcscat( nameW.Buffer, dlloverridesW );
```

### Problem

`malloc` return is not checked. If it fails, `nameW.Buffer` is NULL and the
`wcscpy` immediately crashes. The already-opened `root` key handle would also
be leaked.

### Fix

```c
nameW.Buffer = malloc( len * sizeof(WCHAR) );
if (!nameW.Buffer) { NtClose( root ); return 0; }
wcscpy( nameW.Buffer, app_name );
wcscat( nameW.Buffer, dlloverridesW );
```
