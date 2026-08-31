# OGVCS-045 candidate: untrusted parser boundary

This candidate defines a closed parser-job/result contract and a deliberately
small test supervisor.  It carries an opaque, broker-owned input handle across
the parser boundary; a test credential is never included in parser environment,
arguments, standard input, or output.

The supervisor requires a launcher to attest every OGVCS-003 sandbox control,
including denied network, credential-free process state, read-only input,
isolated scratch, CPU/memory/process limits.  It passes fixed input, output,
memory, and deadline ceilings to that launcher and fails closed if an attestation
or launcher operation is absent.

This does not implement a Git or Perforce importer, a production credential
broker, a Linux kernel sandbox, CLI submission, or publication.  A production
launcher still needs to enforce (rather than merely attest) the frozen OGVCS-003
controls before this boundary can carry untrusted parsers.
