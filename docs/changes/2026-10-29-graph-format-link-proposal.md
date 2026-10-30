# Decision: leave out the optional file-format link

The owner declined this proposal on October 29, 2026. No change to the shared
file writer is needed or authorized by this proposal.

The Go tool puts a web address in each output file that points to a description
of the file's format. The address is stored under the name `$schema`. Our files
leave it out and still work in BloodHound. One Go comparison check required it.

The proposed change would have added that address to MSSQL's files. The owner
decided the address is unnecessary and told us to exclude that requirement.
The shared writer and CMBP's output therefore stay as they are.

Only the address check is excluded. The output tests still check that each file
can be read as JSON, has the right source label, and contains the expected nodes
and relationships with the right identifiers. The Go output-format test as a
whole remains in the reference comparison.

This decision does not change any graph nodes, relationships, permissions,
evidence labels or custom graph definitions. No production code or dependency
was changed, and no publication or Git action was performed.
