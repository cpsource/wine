# Code Review: dlls/ntdll/unix/env.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/env.c`

---

## Summary

Twelve issues were identified, all in the error-handling category. The file
makes extensive use of `malloc`/`realloc` without checking return values.
The most severe subset are three `realloc` calls that overwrite the source
pointer before checking the return value — if `realloc` returns NULL, the
original allocation is silently leaked and the NULL is immediately
dereferenced.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| 1 | Medium | Error handling | 955 | `set_env_var` | `realloc(*env)` unchecked; leaks env on failure |
| 2 | Medium | Error handling | 1008 | `add_system_dll_path_var` | `realloc(path)` unchecked; leaks path on failure |
| 3 | Medium | Error handling | 1069, 1109 | `expand_value` | initial `malloc` and `realloc(ret)` unchecked; leaks on realloc failure |
| 4 | Medium | Error handling | 616 | `build_wargv` | `malloc(wargv)` unchecked; immediate NULL dereference |
| 5 | Medium | Error handling | 878 | `get_initial_environment` | `malloc(env)` unchecked; immediate NULL dereference |
| 6 | Medium | Error handling | 976 | `append_envA` | `malloc(valueW)` unchecked; NULL passed to `ntdll_umbstowcs` |
| 7 | Medium | Error handling | 1153 | `add_registry_variables` | `malloc(newpath)` unchecked; immediate NULL dereference |
| 8 | Medium | Error handling | 1189 | `get_registry_value` | `malloc(ret)` unchecked; immediate NULL dereference |
| 9 | Medium | Error handling | 1430 | `get_initial_directory` | `malloc(tmp)` unchecked; immediate NULL dereference |
| 10 | Medium | Error handling | 1444 | `get_initial_directory` | `malloc(ret)` unchecked; immediate NULL dereference |
| 11 | Medium | Error handling | 551 | `prepend_argv` | `malloc(new_argv)` unchecked; immediate NULL dereference |
| 12 | Medium | Error handling | 1630 | `copy_dos_path_string` | `malloc(nt_str->Buffer)` unchecked; immediate NULL dereference |

---

## Issue 1 — `set_env_var`: `realloc(*env)` not checked

**Lines**: 952–956
**Function**: `set_env_var`

```c
if (*pos + namelen + len + 3 > *size)
{
    *size = max( *size * 2, *pos + namelen + len + 3 );
    *env = realloc( *env, *size * sizeof(WCHAR) );   /* return not checked */
}
memcpy( *env + *pos, name, namelen * sizeof(WCHAR) );  /* crash if NULL */
```

`realloc` return is assigned directly back to `*env`. If it returns NULL, the
original environment block is leaked and `*env` becomes NULL; the `memcpy` at
line 957 immediately dereferences it. `set_env_var` is the central routine
called whenever any environment variable is written, making this a high-impact
path.

**Fix**:
```c
WCHAR *tmp = realloc( *env, *size * sizeof(WCHAR) );
if (!tmp) { *size = 0; return; }
*env = tmp;
```

---

## Issue 2 — `add_system_dll_path_var`: `realloc(path)` not checked

**Lines**: 1007–1009
**Function**: `add_system_dll_path_var`

```c
size_t len = wcslen( nt_name );
path = realloc( path, (path_len + len + 1) * sizeof(WCHAR) );  /* return not checked */
memcpy( path + path_len, nt_name, len * sizeof(WCHAR) );        /* crash if NULL */
```

Same pattern: `realloc` result assigned back to `path`; on failure, the previous
`path` buffer is leaked and `memcpy` crashes.

**Fix**:
```c
WCHAR *tmp = realloc( path, (path_len + len + 1) * sizeof(WCHAR) );
if (!tmp) { free( path ); free( nt_name ); break; }
path = tmp;
```

---

## Issue 3 — `expand_value`: both `malloc` and `realloc` unchecked

**Lines**: 1069, 1109
**Function**: `expand_value`

```c
/* line 1069 — initial allocation */
ret = malloc( retlen * sizeof(WCHAR) );   /* not checked */
while (src_len)
{
    ...
    if (len >= retlen - count)
    {
        retlen = max( retlen * 2, count + len + 1 );
        ret = realloc( ret, retlen * sizeof(WCHAR) );  /* line 1109 — not checked; leaks ret */
    }
    memcpy( ret + count, var, len * sizeof(WCHAR) );   /* line 1111 — crash if NULL */
```

Two problems: (a) if the initial `malloc` fails, `ret` is NULL and `memcpy` at
line 1111 crashes on the first iteration; (b) if `realloc` fails, the original
buffer is leaked and `memcpy` crashes on the same iteration. `expand_value` is
called for every `REG_EXPAND_SZ` registry value during environment setup.

**Fix**:
```c
if (!(ret = malloc( retlen * sizeof(WCHAR) ))) return NULL;
...
    WCHAR *tmp = realloc( ret, retlen * sizeof(WCHAR) );
    if (!tmp) { free( ret ); return NULL; }
    ret = tmp;
```

---

## Issue 4 — `build_wargv`: `malloc(wargv)` not checked

**Line**: 616
**Function**: `build_wargv`

```c
wargv = malloc( total * sizeof(WCHAR) + (argc + 1) * sizeof(*wargv) );
p = (WCHAR *)(wargv + argc + 1);   /* crash if wargv == NULL */
```

**Fix**: `if (!(wargv = malloc(...))) return NULL;`

---

## Issue 5 — `get_initial_environment`: `malloc(env)` not checked

**Line**: 878
**Function**: `get_initial_environment`

```c
env = malloc( *size * sizeof(WCHAR) );
ptr = env;           /* ptr = NULL on failure */
end = env + *size - 1;  /* end = invalid on failure */
for (e = environ; *e && ptr < end; e++)
{
    /* writes through ptr */
```

**Fix**: `if (!(env = malloc( *size * sizeof(WCHAR) ))) return NULL;`

---

## Issue 6 — `append_envA`: `malloc(valueW)` not checked

**Lines**: 975–977
**Function**: `append_envA`

```c
SIZE_T len = strlen(value) + 1;
WCHAR *valueW = malloc( len * sizeof(WCHAR) );
ntdll_umbstowcs( value, len, valueW, len );   /* writes to NULL if malloc failed */
```

**Fix**: `if (!(valueW = malloc( len * sizeof(WCHAR) ))) return;`

---

## Issue 7 — `add_registry_variables`: `malloc(newpath)` not checked

**Lines**: 1153–1154
**Function**: `add_registry_variables`

```c
WCHAR *newpath = malloc( (wcslen(p) - 3 + wcslen(value)) * sizeof(WCHAR) );
wcscpy( newpath, p + 5 );   /* crash if newpath == NULL */
```

**Fix**: `if (!(newpath = malloc(...))) { if (value != data) free(value); continue; }`

---

## Issue 8 — `get_registry_value`: `malloc(ret)` not checked

**Lines**: 1189–1190
**Function**: `get_registry_value`

```c
ret = malloc( len + sizeof(WCHAR) );
memcpy( ret, info->Data, len );   /* crash if ret == NULL */
```

**Fix**: `if (!(ret = malloc( len + sizeof(WCHAR) ))) return NULL;`

---

## Issue 9 — `get_initial_directory` (first site): `malloc(tmp)` not checked

**Lines**: 1430–1431
**Function**: `get_initial_directory`

```c
WCHAR *tmp = malloc( (len + 2) * sizeof(WCHAR) );
wcscpy( tmp, ret );   /* crash if tmp == NULL */
```

**Fix**: `if (!tmp) return ret;  /* return without trailing backslash */`

---

## Issue 10 — `get_initial_directory` (second site): `malloc(ret)` not checked

**Line**: 1444
**Function**: `get_initial_directory`

```c
ret = malloc( sizeof(windows_dir) );
wcscpy( ret, windows_dir );   /* crash if ret == NULL */
```

**Fix**: `if (!(ret = malloc( sizeof(windows_dir) ))) return NULL;`

---

## Issue 11 — `prepend_argv`: `malloc(new_argv)` not checked

**Lines**: 551–552
**Function**: `prepend_argv`

```c
new_argv = malloc( (new_argc + 1) * sizeof(*new_argv) + total );
p = (char *)(new_argv + new_argc + 1);   /* crash if new_argv == NULL */
```

**Fix**: `if (!(new_argv = malloc(...))) return;`

---

## Issue 12 — `copy_dos_path_string`: `malloc(nt_str->Buffer)` not checked

**Lines**: 1630–1631
**Function**: `copy_dos_path_string`

```c
nt_str->Buffer = malloc( len + sizeof(WCHAR) );
memcpy( nt_str->Buffer, *src, len );   /* crash if Buffer == NULL */
```

**Fix**: `if (!(nt_str->Buffer = malloc( len + sizeof(WCHAR) ))) return;`
