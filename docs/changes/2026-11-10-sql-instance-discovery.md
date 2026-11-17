# Shared SQL instance discovery

The owner approved moving SQL address/SPN parsing and SQL Browser resolution
into this library and updating both collectors to use them. The earlier SCCM
collector could select the first instance and default an unresolved name to
1433. MSSQL already had Browser resolution, but its implementation imported
collector target records and graph identifiers, so it could not be reused here.

## How the shared helpers work

`discovery/sql_server.py:parse_sql_address` returns the host, optional instance,
and known numeric port in `SqlAddress`. A plain connection hostname requests
the conventional 1433 port. A named instance has no known port until supplied or
resolved. `parse_sql_spn` also leaves a bare registration's port unknown. Numeric
ports must be in 1..65535; invalid values cannot become a default. This matters
because a named instance and the default engine may have different accounts and
protection settings on the same host.

`clients/mssql.py:parse_target` calls that parser and requires a known port before
connection or EPA work. Existing callers that supplied unresolved names or bad
ports now receive a visible `ValueError`. Callers supplying a bare connection
hostname or a valid numeric port retain their normal selection.

`discovery/sql_browser.py:SqlBrowserResolver` sends a request for one specific
instance to UDP/1434. Its connected socket accepts replies from that destination,
and closes on success or failure. The reply reader checks the header, declared
length, termination, duplicate keys, matching instance and numeric TCP port.
Only successful answers enter its host/instance cache. An enclosing read supplies
its remaining time, deadline and stop event. Proxy mode fails before opening UDP;
the current SOCKS transport carries TCP only. Consumers can avoid Browser by
supplying a known port.

The request limit is 32 encoded bytes, not the earlier 128. The protocol uses a
common system code page. ASCII names are a portable subset; callers knowing the
actual common code page can supply its codec. The implementation does not infer
the remote server's code page from Linux or Windows locale. Unrelated localized
values remain bytes, so a localized server name cannot prevent parsing the ASCII
TCP-port field. Collector command options have not been expanded.

## Why this boundary was selected

Both collectors need the same SQL wire behavior and interpretation of service
registrations. Keeping separate copies would require fixing both repeatedly.
Importing an extension from another extension would couple packaging and graph
rules. Moving the whole MSSQL target record into common would also move its
graph identity policy, which intentionally differs from SCCM's. The shared
helpers therefore accept host/instance values and return connection evidence.
Each collector retains its own target, scope, identity and failure decisions.

Registry inventory, SCCM site mapping, SQL queries and service-account inference
stay in their collectors. The existing shared authentication and LDAP clients
are reused. No dependency, graph schema, relationship kind or OpenHound core
change is needed. Development continues to use this local checkout; publication
and the final dependency minimum remain separate owner-controlled release work.

## Verification

`tests/test_sql_discovery.py` covers unknown ports, numeric limits, connection
rejection before resolution, malformed replies, wrong instances, duplicate keys,
localized values, an explicitly selected code page, the 32-byte limit, success
caching, failed-reply retry, proxy refusal and inherited read controls. Inert
sockets keep these checks independent of the lab and Internet.

The full library suite passed on Windows (700 passed, one skipped) and WSL
(699 passed, two skipped). Ruff and mypy passed; common has 67 checked source
files. Both consumers passed their affected checks on both platforms. Fresh
local-wheel imports/help passed without source redirects. Windows and WSL SCCM
collection retained the three lab engines independently, and MSSQL's named-instance
end-to-end collection produced the same existing graph identifier on each system.
Windows also directly resolved CONFIGMGRSEC through Browser to port 1433.
No lab service or setting was changed. The cached CMBP graph remained 99 nodes
and 307 edges with no differences except last_seen.

The owner approved SCCM's separate site-port policy: keep explained low-privilege
1433 assumptions while preferring collected answers. That policy stays in SCCM.
The outside-repository commit guide was exercised for final local wheels and
both consumers: 53 affected common checks, 252 SCCM checks and 124 MSSQL checks
passed on each platform, with clean lint/types and live named resolution.
The guide is `C:\Users\domainadmin\commit-guide-sql-instance-evidence-2026-11-10.md`.

## Protocol references

The implementation was checked against Microsoft's current documentation on
2026-11-10. These rules describe SQL Server's protocol, not an added package:

- [SQL SPN formats](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17):
  numeric TCP ports and non-TCP instance suffixes have different meanings.
- [Specific-instance Browser request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/c97b04b5-d80f-4d3e-9195-83bbfe246639):
  request byte 0x04, a null terminator and at most 32 encoded name bytes.
- [Browser message encoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/def8dec4-5c2b-4bfd-9531-655de3f74954):
  case-insensitive strings on a common client/server code page.
