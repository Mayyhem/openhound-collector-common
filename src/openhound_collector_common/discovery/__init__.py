"""Target/host discovery helpers for OpenHound collectors.

Modules:
- ``dns`` — domain-controller discovery (SRV ``_ldap._tcp`` then A record) and a
  proxy-aware DNS resolver override.
- ``network`` — shared name resolution and TCP reachability checks.
- ``domain`` — domain selection and LDAP-verified target suffixes.
- ``sql_server`` — SQL host/instance/port parsing without guessed instance ports.
- ``sql_browser`` — validated named-instance port discovery over UDP.
- ``sql_fallback`` — one conventional-port candidate per host and SQL identity validation.
"""
