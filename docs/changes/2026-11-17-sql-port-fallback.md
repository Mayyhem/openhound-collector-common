# Try an unresolved SQL host on 1433 without inventing its instance identity

## Problem and decision

The collectors previously stopped resolving a named SQL instance when its port
could not be determined. That missed named engines which actually listen on TCP
1433, particularly through SOCKS: the existing proxy supports TCP, while SQL
Browser requires UDP. The owner approved a conventional-port connection attempt
in both collectors, with shared support, on November 17, 2026.

The selected rule separates a candidate address from a verified instance name.
An unresolved `host\REPORTS` remains unresolved while the collector separately
tries anonymous `host:1433`. A TCP open establishes reachability only. SQL's own
answer can establish the responding engine; only a matching identity resolves
REPORTS and permits reusing its registrations/account.

Explicit or previously discovered ports still take precedence. A failed known
port does not trigger this fallback. No port range scan or extra command option
is introduced. Discovery-only and excluded/disabled targets do not use it.

## Shared implementation

- `discovery/sql_fallback.py:SqlPortFallback` owns one run's thread-safe record
  of covered 1433 endpoints. `remember` covers known targets before workers
  start; `claim` returns one anonymous `SqlAddress`, or None when already covered.
  Hostnames ignore case and a trailing dot. An already collected computer SID can
  cover aliases through `host_identity`, without more directory or DNS queries.
  Without a common collected identity, different hostname aliases are tracked
  separately. The record is discarded after the run, and failed attempts are not
  retried by each unresolved name.
- The record opens no connection and makes no SQL-presence or graph claim. The
  collectors retain their existing scope checks, methods, credentials, TCP
  clients, SOCKS handling and time limits. One fallback endpoint can require
  several sockets under ordinary login negotiation and EPA measurement.
- `sql_instance_name` validates the connected engine's `ServerName` and
  `InstanceName` properties. It returns the reported named instance, or the
  explicit marker `MSSQLSERVER` for the default engine. Missing/inconsistent
  results raise `ValueError`; NULL alone never turns an unread result into a
  verified default instance. A server rename or cluster alias is not checked
  against the requested hostname; that would reject legitimate connection names.
- `clients/mssql.py:detect_epa(..., identify_instance=True)` optionally adds
  `instanceName` to its result. `_make_prober` reads identity only on its existing
  successful normal login, before releasing that connection. Modified-binding
  probes and denied logins do not run SQL queries. No additional sign-in is
  required. An ordinary identity-read failure leaves the independent protection
  verdict usable; cancellation and fatal cleanup failures propagate and prevent
  further probe logins. Existing callers keep their previous result shape and
  query sequence unless they request identity.

## Collector behavior and effects

SCCM retains unknown-name raw rows, then measures the anonymous candidate. A
matching authenticated identity associates the original account evidence and
clears that name's resolution failure. Other names remain incomplete. A completed
protection measurement with an unread name stays anonymous and cannot inherit a
named registration's account. An open TCP port without a completed SQL measurement
does not create a fallback SQL node. A rejected run credential prevents further
endpoint connections. Implementation: `collectors/mssql.py:_resolve_endpoints`
and `collect_mssql`, with `SourceContext.sql_port_fallback` and the EPA adapter's
optional `EPAResult.instance_name`.

SCCM preprocessing already accepts a matching observed instance/port. Therefore a
verified fallback can supply a definitive site-instance mapping using the
existing rules. An anonymous measurement cannot do that, cannot prove a static
configuration, and does not remove the existing site-database assumption marker.
The owner-approved lowpriv default graph paths remain available and explained.

MSSQL retains the original raw request and connects an anonymous candidate with
no copied instance name, SPNs or service account. Its ordinary server-properties
query already supplies the identity. `collection/server.py:collect_server`
validates it before instance-specific enrichment and uses the actual name for
later WMI/service-account reads. Only a matching name restores the requested
registration/account. A different engine's usable graph is saved under its own
identity, while the requested target is marked incomplete. Missing identity
retains anonymous partial evidence; login denial does not infer a default-engine
WMI account. `collection/browser.py:InstanceResolver` and `collection/run.py`
own the local target and completion choices.

If another requested name on the same host has already consumed the fallback,
the next unresolved name stays incomplete rather than running another catalog
collection. Any actual engine facts already collected remain in the output.
Existing graph identifier rules, schemas, dependencies and authentication modes
are unchanged. Low-level `parse_target` remains strict: a caller must choose a
numeric connection address rather than silently rewriting an unresolved name.
Both collectors continue using the local shared checkout/wheels until the
owner's planned combined release; published consumer minimums remain release work.

## Alternatives

- Stop after Browser failure: avoids a guess but misses reachable named engines
  on 1433; that is the problem this change fixes.
- Treat a successful 1433 connection as REPORTS: can attach another engine's
  databases, privileges and service account to REPORTS. Rejected.
- Scan additional ports or add a UDP proxy implementation: substantially broader
  traffic, options and transport work than the approved single-port fallback.
- Duplicate tracking/identity rules in both extensions: creates two versions of
  the same evidence rule. Common is the right home for those reusable pieces;
  collection order, saved tables and graph/completion policy remain local.
- Add an extra SQL login solely for SCCM identity: unnecessary; the successful
  normal EPA connection can answer the question before it closes.

## Verification and manual checks

The single outside-repository guide is
`C:\Users\domainadmin\commit-guide-sql-instance-evidence-2026-11-10.md`.
It contains the complete numbered commands, expected output and owner-run
commit steps for the pending SQL and SOCKS changes. No git actions were performed
by the agent. The guide's checks were exercised on November 17, 2026.

Affected tests passed on both Windows and WSL: common **127**, SCCM **257**, and
MSSQL **141** per platform. Full source/test Ruff and native mypy checks passed
for all three projects (68/66/62 source files respectively). New standalone
files pass the formatter. Wheels/source archives built, and fresh local-wheel
environments passed installed-import and both collector help checks. The cached
SCCM comparison retained **99 nodes / 307 edges**, with no changes except
`last_seen`. Repository virtual environments were left alone.

Offline cases cover matching/different/default/unread names, retained account
boundaries, anonymous protection results, repeated names and concurrent fallback
claims, known 1433 endpoints, hostname aliases with an existing computer SID,
login denial, cancellation, fatal cleanup and unchanged method/scope gates.

Read-only lab results on both systems:

| Check | Result |
|---|---|
| Direct SCCM administrator collection | Exit 0; CAS/PS1/SEC site-server registry mappings remain definitive |
| Direct named MSSQL collection with a supplied port | Exit 0; existing CONFIGMGRSEC graph identity retained |
| SCCM direct fallback with deliberately unavailable Browser discovery | The real SQL engine identifies CONFIGMGRSEC on 1433; complete |
| SCCM administrator/lowpriv full collection through SOCKS | Exit 0; definitive mappings and explained lowpriv site defaults retained |
| MSSQL through SOCKS with supplied port or no port | Exit 0; the no-port request is verified against the real CONFIGMGRSEC engine |
| MSSQL through SOCKS with deliberately different requested name | Expected exit 3; actual CONFIGMGRSEC graph retained, requested name remains unresolved |
| SCCM isolated fallback through SOCKS, administrator and lowpriv | Both identify the real CONFIGMGRSEC engine on 1433 |
| SCCM isolated fallback through SOCKS, deliberately different name | Actual name/protection retained; requested name remains incomplete |

The additional SCCM fallback cases deliberately fix discovery to one unresolved
registration so this exact condition can be tested without changing server
settings. Direct cases simulate Browser failure; proxied cases use the real
shared UDP restriction. SQL connections, authentication, protection measurements
and identity reads are real. These focused cases do not claim full-pipeline
coverage by themselves; the separate full collector runs above cover the pipeline.
The lab lowpriv account can log into this SQL engine, so missing-login and unread
identity behavior is covered offline rather than claimed as a live result.

Direct and proxied administrator SCCM graphs match at **32 nodes / 60 edges**.
MSSQL graphs match at **163 nodes / 488 edges** for the supplied-port, missing-port
and different-requested-name cases on both platforms. These comparisons exclude
only `last_seen`; identities, relationships, values and source labels match.
The direct baselines explicitly supplied port 1433, so no Browser-label exclusion
was necessary. All **172** audited final proxy connection attempts used the
loopback SOCKS listener. Direct Python connections and datagram sends were
blocked by the test launcher. Both temporary proxies stopped and their closed
listeners were verified. This is a real local SOCKS forwarding check, not a
deployed SSH/C2 tunnel or every-method acceptance run.

Evidence:

- Local wheels/environments, proxy logs and `fallback-final-summary.json`:
  `C:\Users\domainadmin\AppData\Local\Temp\sql-instance-review-ebd24756245847f981e5380781ce12b7`.
  The `final-packages` subfolder contains the final source builds and a second
  fresh Windows environment. The final Linux environment is
  `/home/collector/venvs/sql-fallback-final-ebd24756245847f981e5380781ce12b7`.
  Both final installed environments additionally verified that absent or
  inconsistent identity cannot reuse an available WMI client.
- Direct Windows: `%TEMP%\sql-lab-f232b3b6`; direct WSL:
  `/home/collector/sccm-completion-evidence/sql-review-3bb664cacde2443baeb6a51a39f103b8`.
- Proxied Windows: `%TEMP%\socks-321b267e`; proxied WSL:
  `/home/collector/sccm-completion-evidence/socks-27bbed177f3d4708964b4df15212623e`.
- Cached graph: `%TEMP%\sccm-completion-cache-drd_zq6e`.

Several disposable verification attempts stopped before collection because of
host memory pressure; they were not counted as successful checks. The helper's
starting limit was adjusted from 80 to 85 percent, keeping the collector's own
90 percent safeguard unchanged. Unused WSL file cache was released, idle Debian
was stopped during the Windows phase, and Windows temporarily trimmed this
session's verified VS Code host working set. No process was killed for that trim,
no persistent memory setting changed, and Linux verification restarted Debian.
The [Windows working-set API](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-emptyworkingset)
is a local test-resource action, not part of either collector.

The verifier was also corrected to accept a raw column omitted when all values
are NULL; the original target remains unknown rather than acquiring 1433. Its
initial comparison assumed a Browser label on a baseline that explicitly supplied
the port; the final stronger comparison excludes timestamps only. Neither
correction changed collector behavior. Nondefault ports/multiple engines remain
offline cases; native current-user proxy authentication, all other collection
methods and published-package acceptance remain separate work. WSL output uses
native Linux storage; the separately deferred Windows-copy issue is unchanged.

## References

- [Microsoft SQL network/firewall guidance](https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver17): named engines can use static or dynamic ports; 1433 can be a useful candidate, not an identity guarantee.
- [Microsoft SERVERPROPERTY documentation](https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql): the connected engine reports InstanceName, NULL denotes the default instance, and SQL users can query these properties after login.

The fallback ordering, extra validation and decisions about graph ownership are
local collector/library policy, rather than claims of an automatic SQL client
fallback guaranteed by Microsoft.
