# Code Review: dlls/ntdll/unix/syscall.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/syscall.c`

---

## Summary

No bugs found. The file is a 323-line collection of assembly ABI-fix wrappers,
syscall-table initialisation, and trace helpers. Characteristics that make it
clean:

- No dynamic memory allocation (`malloc`/`realloc`) anywhere.
- All array accesses are bounds-checked (the syscall table is a fixed-size
  array indexed by a compile-time constant).
- No pointer parameters requiring NULL validation at this layer.
- No file descriptors or other resources that could be leaked.
- Trace helpers use stack-allocated buffers with `snprintf`/size-limited paths.

| # | Severity | Category | Line | Function | Short description |
|---|----------|----------|------|----------|-------------------|
| — | — | — | — | — | No issues found |
