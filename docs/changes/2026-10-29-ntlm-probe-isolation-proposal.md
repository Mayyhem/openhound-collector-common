# Proposal: keep the missing-service EPA probe local to its own login

Status: approved by the owner on October 29, 2026; implemented in the working
tree. Verification and the separate hash-input issue are recorded in
[the implementation record](2026-10-29-ntlm-probe-isolation.md). Publication and
full feature-plan acceptance remain pending.

## Problem and evidence

`clients/mssql.py::_Tds.login_epa` currently changes impacket's process-wide
`ntlm.TEST_CASE` flag when testing whether a SQL server accepts authentication
without a service name. That flag is also read by ordinary NTLM authentication.
Two simultaneous logins can therefore change each other's messages. The special
probe also restores a saved flag value that may already belong to another
thread, leaving the flag enabled after both finish.

A disposable, entirely offline check calls the real shared EPA login method
with fake transports and impacket 0.13.1's real NTLMv2 response builder. Events
control the order; the proof does not rely on lucky timing or make a network
connection. It reproduced all three outcomes:

- The ordinary login saw the special test flag enabled.
- Its real NTLMv2 response omitted the service-name field even though that
  ordinary login had not requested the special probe.
- The test flag remained enabled after both logins finished.

The prototype restores the original flag in its final cleanup and writes only
booleans. It does not save authentication packets or use actual credentials.
Evidence is `ntlm-probe-isolation-proof.json` and
`tests/prototype_ntlm_probe_isolation.py` in the private feature task directory.
The prototype is explicitly disposable and is not production code.

## Proposed change and why common is the right home

Remove the global flag change. Add an optional per-call setting to common's
existing NTLM token builder for this one missing-service probe. Normal calls
keep their current provider path. For the special probe, first obtain the normal
provider message, remove only its service-name field, and use impacket's existing
NTLMv2 key/hash/session-key functions to update the affected response and keys.
Then calculate the existing message-integrity check over that final message.
Keep its challenge, timestamp, channel binding and other negotiated fields.

This keeps the decision inside one login's message and memory. It requires no
provider source edit, global override, additional process, new dependency, or
OpenHound core change. Document the small provider-specific boundary against the
installed impacket 0.13.1 code and verify its complete output, not merely that
the field disappeared. Do not introduce custom cryptographic primitives.

Both collectors call common's EPA detection. The fix therefore belongs in common
and should be adopted by both MSSQL and CMBP in the already planned reviewed
shared release. No new collector flag or changed collection default is needed.
Other calls keep their normal service-name field. This is also a recommendation
to update CMBP when that release is available.

## Alternatives

Keeping the global override is unsafe. Locking only this helper does not protect
WMI, HTTP or other provider calls that read the same flag without that lock.
Serializing an entire collection would still miss unrelated callers and discard
useful concurrency. Dropping the probe would lose reference behavior. A separate
process conflicts with the selected in-process direction and is unnecessary for
constructing an owned message. Copying a complete authentication implementation
would add more maintenance and review than the small provider-based boundary.

## Required verification and documentation

Add organized common tests for the reproduced interleaving, concurrent ordinary
auth/probe messages, success and exception cleanup, and an unchanged provider
global throughout. Check the preserved timestamp/challenge/channel binding,
service-name presence/absence, NTLMv2 proof, session key and final integrity check
using the reference vectors and the real provider. Compare ordinary messages
with the unmodified provider under controlled randomness. Verify password and
hash forms; none of these checks needs live credential rejection or lab changes.

At the substantial feature boundary, run the affected common authentication/EPA
tests, MSSQL and SCCM consumer tests, the cached graph checks when relevant, and
the existing authorized read-only lab checks. Update common's record/README and
both collectors' architecture/dependency guidance with the verified behavior.
The owner reviews, commits and publishes; no Git or publication action is part
of this approval.
