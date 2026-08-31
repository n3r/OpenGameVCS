# OGVCS-045 candidate sandbox boundary

This candidate defines a credential-free parser process protocol with a closed,
sorted-key canonical output schema. Its generated canonical manifest pins both
the frozen OGVCS-003 sandbox document and authorization manifest plus the
OGVCS-004/009 predecessor manifests. It does not claim that a JavaScript wrapper
is kernel isolation. A launcher that cannot enforce every listed Linux control
must refuse the job before the parser starts, and a launcher that cannot prove
post-KILL exit settlement cannot return a completed job result.

No Git, Perforce, repository publication, or production credential API is part
of this package.

`ParserResult` permits only the two combinations emitted by the candidate:
`VALIDATED` with `validated` plus a digest, or an allowlisted denial code with
`denied` plus a null digest. The independently maintained validator checks the
complete schema documents, including exact required sets, constraints, and the
full 12-case canary mapping. Its default `npm run check` and `npm test` are
self-contained in the packed package; repository source validation additionally
runs the explicitly source-only `npm run check:predecessors` gate.
