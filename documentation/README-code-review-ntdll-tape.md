# Code Review: dlls/ntdll/unix/tape.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/tape.c`

---

## Summary

No bugs found. The file wraps Unix tape-device `ioctl` calls for Windows
`TAPE_*` I/O controls. Characteristics that make it clean:

- No dynamic memory allocation; all structures are stack-allocated.
- No `free()` calls, so no use-after-free or double-free risk.
- All ioctl return values flow through `TAPE_GetStatus` which converts
  `errno` to an `NTSTATUS` — not silently ignored.
- File descriptor obtained via `server_get_unix_fd` is released with
  `close(fd)` when `needs_close` is set; all error paths return without
  having obtained the fd, so no leak.
- Parameter validation is correctly deferred to the Windows I/O manager
  layer (standard driver architecture).

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| — | — | — | — | — | No issues found |
