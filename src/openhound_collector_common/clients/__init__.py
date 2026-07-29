"""Pure-Python, in-process auth/transport clients for OpenHound collectors.

Modules (added incrementally):
- ``mssql`` — TDS + TLS-over-TDS + NTLMv2 (EPA CBT/SPN) + Kerberos + SSPI; EPA detection.
- ``auth``  — Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting.
- ``ad``    — LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution.
- ``wmi``   — WMI over impacket DCOM + pywin32 (Win32_GroupUser, Win32_Service).

Import submodules directly, e.g. ``from openhound_collector_common.clients import mssql``.
"""
