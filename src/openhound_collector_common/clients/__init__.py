"""In-process Python and native Windows authentication/transport clients.

Modules (added incrementally):
- ``mssql`` — TDS + TLS-over-TDS + NTLMv2 (EPA CBT/SPN) + Kerberos + SSPI; EPA detection.
- ``auth``  — Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting.
- ``ad``    — LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution.
- ``wmi``   — WMI over impacket DCOM + pywin32 (Win32_GroupUser, Win32_Service).
- ``operations`` — Read budgets, cancellation requests and actual cleanup tracking.
- ``wmi_session`` — Whole-read same-host isolation for explicit WMI credentials.
- ``credential_guard`` — One run's shared record that its sign-in details were rejected.

Import submodules directly, e.g. ``from openhound_collector_common.clients import mssql``.
"""
