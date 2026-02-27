# Code Review: dlls/ntdll/unix/file.c

**Branch:** claude-test-file
**Reviewed:** 2026-02-20
**Reviewer:** Claude (Sonnet 4.6)

---

## Overview

`dlls/ntdll/unix/file.c` is the core Windows-to-Linux file I/O translation layer in Wine's NT syscall implementation. It maps NT file operations (`NtReadFile`, `NtWriteFile`, `NtCreateFile`, `NtQueryDirectoryFile`, etc.) to POSIX equivalents (`pread`, `pwrite`, `open`, `openat`, `readdir`, etc.). The file is approximately 7,885 lines long.

---

## Bugs

### 1. Dead condition — `!&futimens` (line 1876)

```c
#ifdef __APPLE__
    if (!&futimens) return FALSE;  // always false
#endif
```

Taking the address of a symbol is never NULL at runtime. This branch is unreachable dead code. The intent was likely a weak-symbol availability check, which should instead be done at compile time with a `#ifdef HAVE_FUTIMENS` guard or similar autoconf check. If `futimens` were truly unavailable at link time, this would produce a linker error rather than a graceful runtime fallback.

**Severity:** Medium
**Suggested fix:** Replace with a `#ifdef HAVE_FUTIMENS` compile-time guard, or remove the dead branch entirely.

---

### 2. Uninitialized upper bytes of `FileId` in `FileIdGlobalTxDirectoryInformation` (lines 2098–2103)

The adjacent `FileIdExtdBothDirectoryInformation` case correctly zeroes the full 16-byte `FileId` before writing the inode number into the lower 8 bytes:

```c
// FileIdExtdBothDirectoryInformation — correct
memset( &info->FileId, 0, sizeof(info->FileId) );
*(ULONGLONG *)&info->FileId = st->st_ino;
```

The `FileIdGlobalTxDirectoryInformation` case immediately below skips the `memset`:

```c
// FileIdGlobalTxDirectoryInformation — missing memset
info->FileId.QuadPart = st->st_ino;
```

`FILE_ID_128` is 16 bytes; `QuadPart` covers only the lower 8. The upper 8 bytes are left uninitialized and may contain stack garbage.

**Severity:** Medium
**Note:** Recent commits `dab7d8d` and `5f881b6` fixed identical uninitialized-field bugs in related structures (`FileIdExtdBothDirectoryInformation`, `FileIdGlobalTxDirectoryInformation`), suggesting this case was overlooked in the same pass.
**Suggested fix:**
```c
case FileIdGlobalTxDirectoryInformation:
{
    FILE_ID_GLOBAL_TX_DIR_INFORMATION *info = ptr;
    memset( &info->FileId, 0, sizeof(info->FileId) );
    info->FileId.QuadPart = st->st_ino;
    fill_file_info( st, attr, info, FileDirectoryInformation );
}
```

---

## Medium Risk

### 3. Integer overflow in `realloc` (line 3440)

```c
if (pos + MAX_DIR_ENTRY_LEN >= *len / sizeof(WCHAR))
{
    if (!(name = realloc( name, *len * 2 )))
```

`*len * 2` can overflow if `*len` is near `SIZE_MAX`, resulting in undefined behaviour and a likely undersized allocation. Low probability in practice, but technically unsafe.

**Severity:** Low
**Suggested fix:** Use a checked multiply or clamp to a maximum buffer size before calling `realloc`.

---

## Code Quality

### 4. Silent `chdir("/")` fallback in `NtQueryDirectoryFile` (around line 2971)

When saving or restoring the process working directory fails during directory enumeration, the code silently falls back to `chdir("/")`. This is correct defensive behaviour, but the failure is not logged. A `WARN()` trace would aid debugging when this path is hit unexpectedly.

**Severity:** Low
**Suggested fix:** Add `WARN("failed to restore cwd, falling back to /\n");` before the fallback `chdir("/")` call.

---

## Positive Observations

- **Mount point detection** (lines 1666–1671): The `fd_is_mount_point()` logic correctly handles the filesystem root edge case via the `parent.st_ino == st->st_ino` check.
- **Path validation** (lines ~3599–3600): Character validation against `invalid_charsW` and the null-character check are thorough and correct.
- **Lock discipline in directory cache**: The `dir_mutex` coverage around `fchdir()`/`readdir()` sequences is sound.
- **Error path cleanup**: `goto done` patterns with centralized resource release are used consistently throughout macOS-specific code paths.

---

## Summary Table

| # | Location | Severity | Issue |
|---|----------|----------|-------|
| 1 | `file.c:1876` | Medium | `!&futimens` always false — unreachable dead branch |
| 2 | `file.c:2101` | Medium | Upper 8 bytes of `FileId` uninitialized in `FileIdGlobalTxDirectoryInformation` |
| 3 | `file.c:3440` | Low | `*len * 2` integer overflow possible in `realloc` call |
| 4 | `file.c:~2971` | Low | Silent `chdir("/")` fallback — no `WARN()` trace emitted |
