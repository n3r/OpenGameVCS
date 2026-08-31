# OGVCS-045 candidate: untrusted parser boundary

This candidate defines a closed parser-job/result contract and a deliberately
small test supervisor.  It carries an opaque, broker-owned input handle across
the parser boundary; a test credential is never included in parser environment,
arguments, standard input, or output.

The supervisor is deliberately branded as candidate-only and can be constructed
only with the isolated test launcher capability. It requires the complete
OGVCS-003 control inventory, snapshots untrusted records without invoking
getters or nested coercion, bounds acquisition/launch/process/read/shutdown, and
performs a bounded TERM-to-process-group-KILL cleanup sequence. A result is
returned only after exit settlement; unconfirmed post-KILL settlement poisons
the supervisor and rejects. It accepts only zero-exit, stderr-free, duplicate-
free sorted-key canonical output under a closed schema with OGVCS-004 portable
paths. The contract manifest pins the frozen OGVCS-003 document and authorization
manifest plus OGVCS-004 and OGVCS-009 manifests, and authenticates its declared
schemas and executable canaries.

This does not implement a Git or Perforce importer, a production credential
broker, a Linux kernel sandbox, CLI submission, or publication.  A production
launcher still needs to enforce (rather than merely attest) the frozen OGVCS-003
controls before this boundary can carry untrusted parsers.

The follow-up hardening makes launch timeout a settlement protocol rather than
a completed result shortcut: an aborted start must reject after cleanup, or any
late process is stopped and its exit observed; otherwise the supervisor is
poisoned with the safe fatal containment code. Native promises are accepted only
with their pristine inert shape and are observed through a captured intrinsic,
preventing accessor execution and raw launcher errors from crossing the result
boundary. Packed contract checks are self-contained, predecessor verification
is an explicit source gate, and independent semantic validation now rejects
reauthenticated required-field or constraint drift.
