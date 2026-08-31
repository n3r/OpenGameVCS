# OGVCS-045 candidate supervisor

This package provides a bounded broker/process protocol, not a kernel sandbox.
It refuses to launch unless the injected OS launcher attests the complete
OGVCS-003 profile. The broker retains an acquisition credential privately and
the parser launch receives an empty environment, no arguments, canonical stdin,
and an opaque immutable input handle only.
