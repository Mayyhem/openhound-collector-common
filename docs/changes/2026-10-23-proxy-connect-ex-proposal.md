# Prevent DNS from bypassing SOCKS

Status: approved by the owner on October 26, 2026; implementation added to
`proxy/patch.py`, with grouped verification completed as described below.

While connecting the planned TCP DNS path, source inspection found that
dnspython 2.8 uses `socket.connect_ex`. Common's `_ProxiedSocket` overrides
`connect` but inherits `connect_ex`, so that call can connect directly to the
destination without a SOCKS handshake. Existing proxy tests cover `connect`
only. This prevents claiming that the existing socket adapter routes DNS safely.

Proposed correction: override `connect_ex` in the same shared socket class and
perform the existing SOCKS handshake with a finite connection timeout. Preserve
the caller's original socket timeout after connecting. Return the socket-style
error number on connection failure, log the reason, and never retry directly.
For sockets that originally requested immediate return, the SOCKS handshake
will wait up to the configured timeout before returning; document this limit
rather than build a second asynchronous SOCKS implementation.

Add a bounded timeout option to the existing install/context functions, keeping
existing callers valid. Use the DNS budget when installing the collector's run
session. Test actual TCP DNS through a local SOCKS fixture, capture its requested
destination, and exercise rejection, closed proxy, and restoration. No new
dependency, collector-specific import, or direct-network fallback is needed.

This belongs in common: it owns the socket adapter and both collectors use it.
Working around this only in MSSQL discovery would leave other Python clients
and collectors able to bypass their selected proxy.

The implementation uses the existing shared socket deadline so a slow trickle
of handshake bytes cannot extend the overall limit. The default limit is 15
seconds; callers can select a shorter positive finite limit. The run-wide DNS
session supplies its DNS budget. A successful handshake restores the caller's
socket mode; an expired deadline closes the socket and returns a failure code.
The proxy's self-connection exception now checks its port as well as its host:
another service on that same host, such as DNS, still uses the proxy. Loopback
connections retain their existing local behavior.

Source inspected: locked dnspython's `dns/query.py` (`_connect` calls
`connect_ex`) and common's `proxy/patch.py`. See the
[dnspython TCP query documentation](https://dnspython.readthedocs.io/en/stable/query.html#tcp).

Verification: ten `connect_ex` cases and three run-wide network-session cases
passed, including a real local TCP DNS request forwarded through a SOCKS fixture,
caller socket modes, proxy rejection, elapsed-time expiry, and restoration.
The complete shared suite passed 254 tests with one explicit Python-version
skip before adding graph evidence. The later 28-test combined selection and
shared lint/type checks passed. Authorized-lab proxied collection remains part
of final acceptance.
