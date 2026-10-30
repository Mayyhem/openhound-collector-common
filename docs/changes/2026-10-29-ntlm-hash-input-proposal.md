# Proposal: decode textual hashes at the NTLM message boundary

Status: approved by the owner on October 29, 2026, and implemented locally.
Verification is recorded with
[the per-login isolation change](2026-10-29-ntlm-probe-isolation.md).

The required hash-form check found a separate existing defect in
`clients/auth.py::ntlm_type3`. `split_hashes` deliberately returns hexadecimal
text because Kerberos callers need text. However, impacket 0.13.1's
`getNTLMSSPType3` expects the actual hash bytes. The shared helper currently
passes text directly. An offline check using the public `User` / `Password` /
`Domain` example succeeds with the password and raises `TypeError` with its
equivalent hash. No network connection or actual credential was used.

Decode the nonempty LM and NT hexadecimal strings to bytes inside
`ntlm_type3`, immediately before calling the NTLM provider. Retain empty strings
for the provider's password path. Leave `split_hashes` and all Kerberos callers
unchanged. The same decoded NT hash will feed the approved missing-service
response update. Malformed hex should fail at this boundary with a safe error
that does not print the value. This is the smallest fix at the boundary that
owns the provider contract; changing the shared splitter would break other
callers.

Both MSSQL and CMBP use common's explicit-credential EPA login, so both benefit.
There is no new dependency, process, collector option, default or graph change.
Verify bare and LM:NT forms against password messages under fixed test
randomness, for both ordinary and missing-service logins; retain invalid-input
and secret-free error checks. Include the fix in the already planned reviewed
common release and report its consumer checks with the isolation work.

Provider source checked against:
https://github.com/fortra/impacket/blob/impacket_0_13_1/impacket/ntlm.py

The initial proposal preceded source edits. After approval, only the NTLM
boundary was changed; `split_hashes` and Kerberos consumers remain unchanged.
