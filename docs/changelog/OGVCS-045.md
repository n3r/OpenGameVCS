# OGVCS-045 candidate: untrusted parser boundary

This candidate defines a closed parser-job/result contract and a deliberately
small test supervisor.  It carries an opaque, broker-owned input handle across
the parser boundary; a test credential is never included in parser environment,
arguments, standard input, or output.

The supervisor is deliberately branded as candidate-only and can be constructed
only with the isolated test launcher capability. It requires the complete
OGVCS-003 control inventory, snapshots untrusted records without invoking
getters, bounds acquisition/launch/stream/shutdown/settlement, and performs a
bounded TERM-to-process-group-KILL cleanup sequence. It accepts only zero-exit,
stderr-free canonical output with closed fields and OGVCS-004 portable paths.
The contract manifest pins the frozen OGVCS-003 profile plus OGVCS-004 and
OGVCS-009 manifests, and authenticates its declared schemas and canaries.

This does not implement a Git or Perforce importer, a production credential
broker, a Linux kernel sandbox, CLI submission, or publication.  A production
launcher still needs to enforce (rather than merely attest) the frozen OGVCS-003
controls before this boundary can carry untrusted parsers.
