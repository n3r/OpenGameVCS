# `ogvcs-chunking-manifest`

Independent scalar Rust implementation of the Proposed ADR-0016
`chunking.opengamevcs/gear-fastcdc-1m@1` candidate. It uses the public
`ogvcs-object-model` crate for SHA-256, ObjectIDs, profile references, and
canonical manifest CBOR. Those public-codec bytes are tested byte-for-byte
against the independent language-neutral oracle. Switching to the public
registry-aware streaming writer remains an integration step after the candidate
profile enters the shared registry.

This authority cut is not production-write eligible and does not claim CLI,
workspace reconstruction, benchmark selection, or 100-GiB evidence.

This scalar cut admits one worker, no completed-chunk queue, and the exact
ADR-0016 scalar working-memory budget of 4,259,840 bytes.
