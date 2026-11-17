# Handle unavailable destinations through SOCKS

The owner approved this shared-library change after live SCCM collection found
that an ordinary refused SQL port marked a proxied run incomplete. A direct
connection raised a normal socket error, while the proxy's equivalent reply
raised `SocksError`, outside SCCM's port-check handler.

## How the correction works

`proxy/socks.py:_socks5_connect` reads the complete SOCKS reply, checks its version,
reserved field and address format, and consumes its bound port before selecting
an error. An incomplete or malformed reply remains `SocksError` even if its reply
code claims that the destination refused the connection.

Only the following explicit destination replies become ordinary socket errors:

| SOCKS reply | Meaning | Python error number |
|---|---|---|
| 3 | Network unreachable | `errno.ENETUNREACH` |
| 4 | Host unreachable | `errno.EHOSTUNREACH` |
| 5 | Connection refused | `errno.ECONNREFUSED` |

The raised `OSError` includes that platform's error number, the destination host
and port, and the readable SOCKS reason. Python selects `ConnectionRefusedError`
for refusal. A collector's existing socket-error handler can therefore handle
these failures in the same way as a direct connection. Other replies, including
general server failure, policy denial, TTL expiry and unsupported commands or
address types, remain `SocksError`. Authentication failures also remain separate.
The error message does not contain proxy credentials.

`proxy/patch.py:_ProxiedSocket.connect_ex` returns the destination error number.
For proxy/protocol failures it returns `errno.EIO` and logs the specific reason,
instead of returning connection refused for every kind of failure. Existing
timeout handling still returns `ETIMEDOUT`. No failure retries the destination
directly. The dialer's existing cleanup closes its socket when negotiation fails.

The mapping follows the reply meanings in
[RFC 1928 section 6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6).
Python's documented
[OSError constructor](https://docs.python.org/3.13/library/exceptions.html#OSError)
selects the corresponding built-in subclass from the error number. The selected
mapping is library policy; the RFC does not prescribe Python exception types.

## Why it belongs here

Both SCCM and MSSQL use the same shared socket interception. Other Python clients
using it also expect ordinary socket errors for unavailable destinations. Fixing
the shared SOCKS boundary avoids a different exception workaround in each
collector. There is no new dependency, command option, graph identifier, schema,
node or edge. The change affects collection transport only; graph preparation and
conversion are unchanged. Consumers need the updated local common checkout or
its built wheel; publication and minimum-version updates remain separate work.

Catching every `SocksError` in SCCM was rejected because it would treat proxy
authentication or protocol failures as evidence about a SQL listener. Making all
`SocksError` instances ordinary socket errors has the same problem. Translating
only the three explicit destination replies keeps that distinction and avoids
introducing a new exception hierarchy for callers to learn.

## Verification and manual checks

The new regression checks failed before the correction and passed afterward.
They exercise IPv4, IPv6 and hostname reply layouts, the three destination error
numbers, refusal's Python exception type, socket cleanup, authentication and
malformed/truncated replies. Real loopback proxy fixtures exercise
`create_connection`, `connect` and `connect_ex`, including preservation of error
numbers and the absence of a direct retry. The fixture enhancement preserves the
existing successful echo behavior.

The broader affected checks passed on Windows and WSL: common 110, SCCM 252,
and MSSQL 124 tests on each platform. Full source/test Ruff checks and native
mypy passed in all three projects. A cached SCCM graph retained 99 nodes and
307 edges, with zero differences after excluding only `last_seen`. All three
projects built wheels and source archives; fresh Windows and WSL environments
installed those local wheels and passed installed-import and collector-help
checks without source redirects.

The existing outside-repository review guide also includes real lab collection
through SOCKS on both systems:
`C:\Users\domainadmin\commit-guide-sql-instance-evidence-2026-11-10.md`.
It contains the full copyable commands, expected output, manual verification
steps, cleanup and owner-run commit commands. No staging, commit or push is done
by the agent.

Installed live checks passed on both platforms. SCCM administrator and lowpriv
SOCKS runs now exit 0, including the two hosts with refused SQL ports. Definitive
site mappings and explained lowpriv assumptions remain intact. Known-port MSSQL
collection exits 0 and keeps its named-instance identity; the unresolved-port
case still exits 1 with the expected UDP Browser warning and no graph archive.
All 114 audited collector connection attempts went to the proxy, with no direct
or datagram attempt. Both temporary forwarders stopped afterward.

Direct and SOCKS SCCM graphs match at 32 nodes and 60 edges on each platform.
MSSQL graphs match at 163 nodes and 488 edges, allowing collection timestamps and
only the expected SQLBrowser evidence label on the direct run, which discovered
the port instead of receiving it explicitly. No other graph difference remains.
The guide's complete Checks section was exercised, with successful retries
after the unchanged memory safeguard stopped earlier Windows attempts.

Final packages, environments, proxy logs and `socks-final-summary.json`:
`%TEMP%\sql-instance-review-bc65db1ca2d345e0a6fb6a6683c7ba18`.
Final Windows SOCKS data: `%TEMP%\socks-803e89e6`. Final WSL SOCKS data:
`/home/collector/sccm-completion-evidence/socks-02361e12c5ab487b8e54eaffae999c79`.
Forwarders run separately on Windows and WSL to keep memory use manageable;
the collector's 90 percent limit is unchanged. This is a local real-forwarding
check, not a deployed SSH/C2 tunnel or every-protocol acceptance test.
