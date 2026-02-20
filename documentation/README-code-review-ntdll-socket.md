# Code Review: dlls/ntdll/unix/socket.c

**Reviewer**: Claude Code
**Date**: 2026-02-20
**File**: `dlls/ntdll/unix/socket.c`

---

## Summary

Six issues were identified ranging from high-severity functional bugs to low-severity
code quality concerns.

| # | Severity | Category | Line(s) | Short description |
|---|----------|----------|---------|-------------------|
| 1 | High | Bug | 2397 | `IPPROTO_IP` instead of `IPPROTO_IPV6` in `SET_IPV6_DONTFRAG` fallback |
| 2 | High | Bug | 551 | `memcpy` overreads source buffer in `wow64_translate_control` |
| 3 | High | Bug | 1068 | Port-0 substitution only patches IPv4 field when family is IPv6 |
| 4 | Medium | Bug | 1050 | Unchecked `getsockopt` leaves `sock_type` uninitialized |
| 5 | Low | Code quality | 350 | `SOCKADDR_IRDA` not zero-initialized, leaks padding bytes |
| 6 | Low | Code quality | 558 | Stale `FIXME` trace fires on every WoW64 control-message translation |

---

## Issue 1 — High: Wrong protocol in `IOCTL_AFD_WINE_SET_IPV6_DONTFRAG` fallback

**Line**: 2397
**Function**: `sock_ioctl` / `IOCTL_AFD_WINE_SET_IPV6_DONTFRAG` case

### Code

```c
case IOCTL_AFD_WINE_SET_IPV6_DONTFRAG:
#ifdef IPV6_DONTFRAG
    return do_setsockopt( handle, io, IPPROTO_IPV6, IPV6_DONTFRAG, in_buffer, in_size );
#elif defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO) && defined(IPV6_PMTUDISC_DONT)
{
    int value = *(DWORD *)in_buffer ? IPV6_PMTUDISC_DO : IPV6_PMTUDISC_DONT;

    return do_setsockopt( handle, io, IPPROTO_IP, IPV6_MTU_DISCOVER, &value, sizeof(value) );
    //                               ^^^^^^^^^^^ should be IPPROTO_IPV6
}
```

### Problem

The `#elif` fallback (used on Linux systems that have `IPV6_MTU_DISCOVER` but
not `IPV6_DONTFRAG`) passes `IPPROTO_IP` (the IPv4 protocol level) instead of
`IPPROTO_IPV6`. The `setsockopt` call will either fail with `ENOPROTOOPT` or
silently modify an unintended IPv4 socket option. This covers the majority of
Linux deployments, so the IPv6 don't-fragment setting is effectively broken on
Linux whenever the primary `#ifdef IPV6_DONTFRAG` path is not taken.

### Fix

```c
- return do_setsockopt( handle, io, IPPROTO_IP,   IPV6_MTU_DISCOVER, &value, sizeof(value) );
+ return do_setsockopt( handle, io, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value) );
```

---

## Issue 2 — High: `memcpy` overreads source buffer in `wow64_translate_control`

**Line**: 551
**Function**: `wow64_translate_control`

### Code

```c
cmsg32->cmsg_len = cmsg64->cmsg_len - sizeof(*cmsg64) + sizeof(*cmsg32);
cmsg32->cmsg_level = cmsg64->cmsg_level;
cmsg32->cmsg_type = cmsg64->cmsg_type;
memcpy( cmsg32 + 1, cmsg64 + 1, cmsg64->cmsg_len );   // wrong length
```

### Problem

`cmsg64 + 1` points to the **data** portion of the 64-bit control message.
That data region is `cmsg64->cmsg_len - sizeof(*cmsg64)` bytes long.
Passing the full `cmsg64->cmsg_len` as the copy length causes `memcpy` to
read `sizeof(WSACMSGHDR)` bytes past the end of the data — into the next
control message header or past the end of the control buffer entirely.

The overflow check at line 542 uses a size derived from the miscomputed
`cmsg_align_32(cmsg64->cmsg_len)` and does not catch the overread.

This affects any 32-bit application running under WoW64 that receives
ancillary data (e.g. `IP_PKTINFO`, `IP_TTL`, `SO_TIMESTAMP`) via `recvmsg`.

### Fix

```c
size_t data_len = cmsg64->cmsg_len - sizeof(*cmsg64);
memcpy( cmsg32 + 1, cmsg64 + 1, data_len );
```

---

## Issue 3 — High: Port-0 substitution writes IPv4 field for IPv6 sockets

**Line**: 1068
**Function**: `sock_send` (linux send path)

### Code

```c
if (sock_type == SOCK_DGRAM && ((unix_addr.addr.sa_family == AF_INET  && !unix_addr.in.sin_port)
                             || (unix_addr.addr.sa_family == AF_INET6 && !unix_addr.in6.sin6_port)))
{
    WARN( "Trying to use destination port 0, substituing 9.\n" );
    unix_addr.in.sin_port = htons( 9 );   // only the IPv4 field is written
}
```

### Problem

When the destination address family is `AF_INET6` and the port is 0, the code
enters the branch but writes `unix_addr.in.sin_port` (the `sockaddr_in` field)
instead of `unix_addr.in6.sin6_port` (the `sockaddr_in6` field). The IPv6 port
remains 0, so `sendmsg` still fails — the substitution has no effect for IPv6
UDP sockets.

The log message also contains a typo: `"substituing"` should be
`"substituting"`.

### Fix

```c
WARN( "Trying to use destination port 0, substituting 9.\n" );
if (unix_addr.addr.sa_family == AF_INET6)
    unix_addr.in6.sin6_port = htons( 9 );
else
    unix_addr.in.sin_port = htons( 9 );
```

---

## Issue 4 — Medium: Unchecked `getsockopt` leaves `sock_type` uninitialized

**Line**: 1050
**Function**: `sock_send` (linux send path)

### Code

```c
int sock_type;
socklen_t len = sizeof(sock_type);
ssize_t ret;

getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &len);  // return value ignored

// ...
if (async->addr && sock_type != SOCK_STREAM)            // sock_type may be garbage
```

### Problem

If `getsockopt` fails, `sock_type` is never written and remains uninitialized.
The comparisons at lines 1053 and 1062 then produce undefined behaviour.
On a valid, open socket descriptor this is unlikely to fail, but the omission
is technically incorrect and will misfire on any error path that reaches
this code with a bad fd.

### Fix

```c
if (getsockopt( fd, SOL_SOCKET, SO_TYPE, &sock_type, &len ) < 0)
{
    WARN( "getsockopt SO_TYPE failed: %s\n", strerror(errno) );
    return sock_errno_to_status( errno );
}
```

---

## Issue 5 — Low: `SOCKADDR_IRDA` not zero-initialized, leaks padding bytes

**Line**: 350
**Function**: `sockaddr_from_unix`

### Code

```c
case AF_IRDA:
{
    SOCKADDR_IRDA win;      // not zero-initialized; compare AF_INET at line 306: "= {0}"

    if (wsaddrlen < sizeof(win)) return -1;
    win.irdaAddressFamily = WS_AF_IRDA;
    memcpy( win.irdaDeviceID, &uaddr->irda.sir_addr, sizeof(win.irdaDeviceID) );
    // ...
    memcpy( wsaddr, &win, sizeof(win) );
```

### Problem

Every other address-family branch in `sockaddr_from_unix` initializes its
local structure with `= {0}` before selectively filling fields. The `AF_IRDA`
case does not, so any padding bytes inside `SOCKADDR_IRDA` retain whatever
stack values were present and are then copied verbatim to the caller's buffer.

### Fix

```c
- SOCKADDR_IRDA win;
+ SOCKADDR_IRDA win = {0};
```

---

## Issue 6 — Low: Stale `FIXME` trace fires on every successful WoW64 control-message translation

**Line**: 558
**Function**: `wow64_translate_control`

### Code

```c
control32->len = ptr32 - buf32;
FIXME("-> %d\n", control32->len);
return 1;
```

### Problem

This `FIXME` trace is reached on every **successful** translation of ancillary
data for a 32-bit application under WoW64. Any WoW64 program that calls
`recvmsg` with a control buffer (common for UDP applications using `IP_PKTINFO`
or `SO_TIMESTAMP`) will generate a `FIXME` log line on every receive, producing
significant log spam and potentially masking real issues.

### Fix

Remove the line, or demote it to `TRACE` if the value is still useful for
debugging:

```c
- FIXME("-> %d\n", control32->len);
+ TRACE("-> %d\n", control32->len);
```
