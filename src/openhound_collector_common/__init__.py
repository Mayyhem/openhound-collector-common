"""Shared pure-Python infrastructure for OpenHound on-prem / Windows-auth collectors.

This package factors out the generic, non-REST collector machinery first proven in the
SCCM extension (``sccm/sccm/src/openhound_sccm/``) so multiple collectors (starting with
``mssql``) can reuse it without duplication. Windows AD/WMI collection remains
in process, with optional cancellation requests and actual cleanup tracking.
Native calls can overrun a requested timeout; no separate authentication tool
or database driver is added.

Subpackages (added incrementally — see the design spec under
``mssql/mssql/docs/superpowers/specs/``):

- ``clients``    — TDS+TLS+NTLM+Kerberos+EPA (``mssql``), token minting (``auth``),
                   LDAP/AD + SID resolution (``ad``), WMI over DCOM/SSPI (``wmi``).
- ``discovery``  — DNS SRV/A based DC + SPN discovery.
- ``dlt``        — push→pull source bridge, progress display choices, DuckDB-safe helpers.
- ``logging``    — VERBOSE tier + ``[target]``/``[phase]`` contextvar tagging.
- ``graph``      — generic edge model + edge-endpoint stub-node backfill.
- ``proxy``      — pure-Python SOCKS5 dialer.
"""

__version__ = "0.0.1"
