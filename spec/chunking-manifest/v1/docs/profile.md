# Candidate profile semantics

ADR-0016 is normative for the candidate. This packaged summary exists for
offline consumers.

- Profile: `chunking.opengamevcs/gear-fastcdc-1m@1`
- Determinism tuple: exact logical bytes plus canonical repository-selected
  profile/policy.
- Empty: zero chunks.
- Whole class: lengths 1 through 262,144, exactly one chunk.
- CDC class: minimum 262,144; target 1,048,576; maximum 2,097,152 bytes.
- Recurrence: `fp = ((fp << 1) + GEAR[inputByte]) mod 2^64`, reset per chunk.
- Early mask: `0x00000000001fffff` for eligible lengths below target.
- Late mask: `0x000000000007ffff` at and above target.
- Cut after the byte when the masked fingerprint is zero, or force at maximum.
- EOF emits one nonempty suffix; empty input emits nothing.
- Profile verification recomputes and compares every boundary in addition to
  OGVCS-002 chunk and whole-file digest verification.

Table entry `i` is the first eight SHA-256 digest bytes, interpreted uint64be,
of the 26-byte domain `ASCII("OpenGameVCS Gear table v1") || 0x00` followed by
`uint16be(i)`.
