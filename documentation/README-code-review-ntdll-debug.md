# Code Review: dlls/ntdll/unix/debug.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/debug.c`

---

## Summary

One issue was identified. The automated agent proposed a second finding
(`write()` returned as `NTSTATUS`); it was rejected as a false positive after
manual verification:

- *`write()` return value used as NTSTATUS in `unixcall_wine_dbg_write`/`wow64_wine_dbg_write`* —
  The PE-side wrapper `__wine_dbg_write` (thread.c line 168) is declared
  `int WINAPI __wine_dbg_write(...)` and its callers in thread.c (lines 76,
  79, 187) all ignore the return value. The `NTSTATUS` return channel is simply
  used to pass the byte-count from `write()` back to the PE side unchanged.
  This is intentional; no misinterpretation occurs.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Medium | Error handling | 120 | `add_option` | `realloc(debug_options)` unchecked; leaks buffer, crashes on write |

---

## Issue 1 — `add_option`: `realloc(debug_options)` not checked

**Lines**: 117–126
**Function**: `add_option`

### Code

```c
if (nb_debug_options >= options_size)
{
    options_size = max( options_size * 2, 16 );
    debug_options = realloc( debug_options, options_size * sizeof(debug_options[0]) );
    /* NULL return not checked — old buffer leaked, NULL written to debug_options */
}

pos = min;
if (pos < nb_debug_options) memmove( &debug_options[pos + 1], &debug_options[pos],
                                     (nb_debug_options - pos) * sizeof(debug_options[0]) );
strcpy( debug_options[pos].name, name );  /* crash if debug_options == NULL */
```

### Problem

`realloc` result is assigned directly back to `debug_options`. If `realloc`
returns NULL, the previous `debug_options` allocation is silently leaked and
`debug_options` becomes NULL. The `memmove` and `strcpy` at lines 124–126
immediately dereference that NULL.

`add_option` is called from `parse_options`, which is called during debug
channel initialisation (via `init_options`). On a memory-constrained system
this can cause a crash during startup while parsing the `WINEDEBUG` environment
variable.

### Fix

```c
if (nb_debug_options >= options_size)
{
    struct __wine_debug_channel *tmp;
    options_size = max( options_size * 2, 16 );
    tmp = realloc( debug_options, options_size * sizeof(debug_options[0]) );
    if (!tmp) return;
    debug_options = tmp;
}
```

On failure, the option is silently skipped (the same outcome as if the channel
name were absent from `WINEDEBUG`), which is far preferable to a crash.
