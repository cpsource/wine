# Code Review: dlls/ntdll/unix/loader.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/loader.c`

---

## Summary

Six issues were identified. The dominant theme is unchecked `malloc` and
`asprintf` return values: Wine's style in the rest of the ntdll/unix layer is
to call `fatal_error`/`fatal_perror` immediately on allocation failure, but
loader.c does not follow this convention consistently, and several sites
produce crashes or heap corruption rather than a diagnostic message.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | Medium | Error handling | 2111–2113 | `asprintf` unchecked in macOS `pre_exec`; failure passes NULL to `setenv` |
| 2 | Medium | Error handling | 2187, 2195 | `asprintf` unchecked in `check_command_line`; uninitialized `exe` passed to `access`/`free` |
| 3 | Medium | Error handling | 1707–1715 | `asprintf` unchecked in `load_ntdll`; NULL `name` passed to `open_builtin_pe_file` and `fatal_error` |
| 4 | Medium | Error handling | 191, 201, 240 | `malloc` unchecked in `remove_tail`, `build_path`, `build_relative_path` |
| 5 | Medium | Error handling | 305, 329 | `malloc` unchecked in `set_dll_path`/`set_system_dll_path`; crash at startup |
| 6 | Low | Error handling | 1491, 1813, 2147, 2153 | `malloc` unchecked in `load_start_exe`, `load_wow64_ntdll`, `reexec_loader` |

---

## Issue 1 — Medium: `asprintf` unchecked in macOS `pre_exec`; failure passes NULL to `setenv`

**Lines**: 2111–2113
**Function**: `pre_exec` (macOS build)

### Code

```c
char *path = getenv( "DYLD_LIBRARY_PATH" );
if (path) asprintf( &path, "%s/dlls/ntdll:%s/dlls/win32u:%s", build_dir, build_dir, path );
else      asprintf( &path, "%s/dlls/ntdll:%s/dlls/win32u", build_dir, build_dir );
setenv( "DYLD_LIBRARY_PATH", path, 1 );
```

### Problem

Two distinct failure modes:

**`else` branch** (`DYLD_LIBRARY_PATH` not set): `asprintf` initialises `path`
only on success. If it fails, `path` retains the value from `getenv`, which
was `NULL`. `setenv("DYLD_LIBRARY_PATH", NULL, 1)` passes a NULL value
pointer; on macOS and glibc this is undefined behaviour and typically a
segfault.

**`if` branch** (`DYLD_LIBRARY_PATH` is set): if `asprintf` fails, `path`
still points into the environment block (a read-only region on some systems).
`setenv` would silently re-write the variable to its old value rather than
prepending the build directory. The loader then starts without the ntdll/win32u
paths on `DYLD_LIBRARY_PATH`, causing dyld to fail to find Wine's shared
libraries.

### Fix

```c
char *path = getenv( "DYLD_LIBRARY_PATH" );
char *new_path;
if (path) {
    if (asprintf( &new_path, "%s/dlls/ntdll:%s/dlls/win32u:%s",
                  build_dir, build_dir, path ) == -1)
        fatal_error( "asprintf" );
} else {
    if (asprintf( &new_path, "%s/dlls/ntdll:%s/dlls/win32u",
                  build_dir, build_dir ) == -1)
        fatal_error( "asprintf" );
}
setenv( "DYLD_LIBRARY_PATH", new_path, 1 );
free( new_path );
```

---

## Issue 2 — Medium: `asprintf` unchecked in `check_command_line`; uninitialized pointer used

**Lines**: 2187, 2195
**Function**: `check_command_line`

### Code

```c
char *exe;   /* uninitialised */

if (build_dir)
{
    asprintf( &exe, "%s/programs/%s%s/%s.exe", build_dir, basename, pe_dir, basename );
    if (!access( exe, R_OK )) reexec_loader( argc, argv, basename );
    free( exe );
}
else
{
    for (int i = 0; dll_paths[i]; i++)
    {
        asprintf( &exe, "%s%s/%s.exe", dll_paths[i], pe_dir, basename );
        if (!access( exe, R_OK )) reexec_loader( argc, argv, basename );
        free( exe );
    }
}
```

### Problem

`exe` is declared but never initialised. If either `asprintf` call fails:

- `access( exe, R_OK )` is called with a garbage or freed pointer —
  undefined behaviour, potential crash or incorrect return value.
- `free( exe )` on a garbage or freed pointer — heap corruption.

In the loop case the first iteration is the most dangerous: if `asprintf`
fails immediately, `exe` holds whatever was on the stack. Subsequent
iterations would pass the freed-but-possibly-recycled pointer from the
previous iteration to `access` and `free`.

### Fix

Initialise `exe` to `NULL` and check `asprintf`:

```c
char *exe = NULL;
...
if (asprintf( &exe, ... ) == -1) fatal_error( "asprintf" );
if (!access( exe, R_OK )) reexec_loader( argc, argv, basename );
free( exe );
exe = NULL;
```

---

## Issue 3 — Medium: `asprintf` unchecked in `load_ntdll`; NULL propagates to `open_builtin_pe_file` and `fatal_error`

**Lines**: 1707–1715
**Function**: `load_ntdll`

### Code

```c
char *name = NULL;
...
if (build_dir) asprintf( &name, "%s%s/ntdll.dll", ntdll_dir, pe_dir );
else           asprintf( &name, "%s%s/ntdll.dll", dll_dir, pe_dir );

status = open_builtin_pe_file( name, &attr, ... );  /* name may be NULL */
if (status == STATUS_DLL_NOT_FOUND)
{
    free( name );                                    /* free(NULL) is fine */
    asprintf( &name, "%s/ntdll.dll%c.so", ntdll_dir, 0 );
    status = open_builtin_so_file( name, &attr, ... );  /* name may be NULL */
}
if (status) fatal_error( "failed to load %s error %x\n", name, status );  /* %s on NULL is UB */
```

### Problem

`name` is initialised to `NULL`. If the first `asprintf` fails it stays
`NULL`. `open_builtin_pe_file(NULL, ...)` may dereference it or pass it
to `open()` immediately, producing a crash rather than a clear diagnostic.

If the first `asprintf` fails **and** `open_builtin_pe_file` returns
`STATUS_DLL_NOT_FOUND` (possible if NULL triggers ENOENT), the second
`asprintf` is also attempted. If that also fails, `name` is still `NULL`,
and `fatal_error("failed to load %s ...", NULL, status)` passes NULL for
`%s` — undefined behaviour (glibc prints `(null)`, MSVC crashes).

### Fix

```c
if (build_dir) {
    if (asprintf( &name, "%s%s/ntdll.dll", ntdll_dir, pe_dir ) == -1)
        fatal_error( "asprintf" );
} else {
    if (asprintf( &name, "%s%s/ntdll.dll", dll_dir, pe_dir ) == -1)
        fatal_error( "asprintf" );
}
```

And similarly for the fallback `.so` path.

---

## Issue 4 — Medium: `malloc` unchecked in `remove_tail`, `build_path`, `build_relative_path`

**Lines**: 191, 201, 240
**Functions**: `remove_tail`, `build_path`, `build_relative_path`

### Code

```c
/* remove_tail, line 191 */
ret = malloc( len - tail_len + 1 );
memcpy( ret, str, len - tail_len );   /* crash if ret == NULL */

/* build_path, line 201 */
char *ret = malloc( len + strlen( name ) + 2 );
...
memcpy( ret, dir, len );              /* crash if ret == NULL */

/* build_relative_path, line 240 */
ret = malloc( strlen(base) + 3 * dotdots + strlen(start) + 2 );
strcpy( ret, base );                  /* crash if ret == NULL */
```

### Problem

All three functions use the `malloc` return value immediately without a NULL
check. On allocation failure each crashes with a NULL dereference instead of
returning an error to the caller.

These functions produce paths that are passed to `open`, `exec`, `dlopen`,
and other critical calls throughout the loader. Every caller silently assumes
the returned string is valid.

`build_relative_path` has an additional integer-overflow risk: `dotdots` is
an `unsigned int` incremented once per path component in the `from` argument.
If `from` contains an extreme number of components, `3 * dotdots` overflows,
producing a tiny allocation followed by `strcat` writing far past the end of
the buffer. This is unlikely in practice but the arithmetic is unchecked.

### Fix

```c
/* build_path */
char *ret = malloc( len + strlen( name ) + 2 );
if (!ret) fatal_error( "malloc" );

/* remove_tail */
ret = malloc( len - tail_len + 1 );
if (!ret) return NULL;   /* caller returns NULL on failure */

/* build_relative_path — also guard overflow */
size_t sz = strlen(base) + (size_t)3 * dotdots + strlen(start) + 2;
if (sz < strlen(base)) return NULL;   /* overflow check */
ret = malloc( sz );
if (!ret) return NULL;
```

---

## Issue 5 — Medium: `malloc` unchecked in `set_dll_path` and `set_system_dll_path`

**Lines**: 305, 329
**Functions**: `set_dll_path`, `set_system_dll_path`

### Code

```c
/* set_dll_path, line 305 */
dll_paths = malloc( (count + 2) * sizeof(*dll_paths) );
count = 0;
if (!build_dir) dll_paths[count++] = dll_dir;   /* crash if malloc failed */

/* set_system_dll_path, line 329 */
system_dll_paths = malloc( (count + 1) * sizeof(*system_dll_paths) );
count = 0;
...
system_dll_paths[count++] = strdup( p );         /* crash if malloc failed */
```

### Problem

Both functions are called during loader initialisation. `dll_paths` and
`system_dll_paths` are global arrays used for every subsequent DLL search.
If either `malloc` returns NULL, the immediate array write (`dll_paths[0]`)
dereferences a NULL pointer and crashes during startup.

Additionally, the `strdup` calls at lines 312, 313, 334, 336 are also
unchecked: a NULL return would insert a NULL entry into the path array,
causing a crash when any code later iterates the array expecting
non-NULL strings.

### Fix

```c
dll_paths = malloc( (count + 2) * sizeof(*dll_paths) );
if (!dll_paths) fatal_error( "malloc" );

/* likewise for each strdup: */
dll_paths[count] = strdup( p );
if (!dll_paths[count]) fatal_error( "strdup" );
count++;
```

---

## Issue 6 — Low: `malloc` unchecked in `load_start_exe`, `load_wow64_ntdll`, `reexec_loader`

**Lines**: 1491, 1813, 2147, 2153
**Functions**: `load_start_exe`, `load_wow64_ntdll`, `reexec_loader`

### Code

```c
/* load_start_exe, line 1491 */
WCHAR *image = malloc( sizeof("\\??\\C:\\windows\\system32\\start.exe") * sizeof(WCHAR) );
wcscpy( image, get_machine_wow64_dir( current_machine ));   /* crash if NULL */

/* load_wow64_ntdll, line 1813 */
path = malloc( sizeof("\\??\\C:\\windows\\system32\\ntdll.dll") * sizeof(WCHAR) );
wcscpy( path, wow64_dir );   /* crash if NULL */

/* reexec_loader, lines 2147, 2153 */
new_argv = malloc( (argc + 3) * sizeof(*argv) );
memcpy( new_argv + 3, argv + 1, argc * sizeof(*argv) );   /* crash if NULL */
```

### Problem

All three functions use the `malloc` result immediately without checking for
`NULL`. On allocation failure each crashes with a NULL dereference rather
than producing a useful error message.

These are all initialisation-time or process-restart paths; an OOM during
process startup should produce a clear diagnostic, not a segfault.

### Fix

Add a NULL check with `fatal_error` after each `malloc`:

```c
WCHAR *image = malloc( ... );
if (!image) fatal_error( "malloc" );

path = malloc( ... );
if (!path) fatal_error( "malloc" );

new_argv = malloc( ... );
if (!new_argv) fatal_error( "malloc" );
```
