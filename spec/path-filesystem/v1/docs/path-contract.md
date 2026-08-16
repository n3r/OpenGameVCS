# Path contract v1

## Canonical input boundary

A repository path is one to 256 OGVCS-002 segment values. Each segment is a
Unicode scalar string already in NFC, contains 1–255 UTF-8 bytes, and is not
empty, `.`, `..`, or a string containing `/`, `\\`, or NUL. The joined display
value inserts exactly one ASCII `/` between segments and is relative. The
joined UTF-8 measure is at most 4,096 bytes. Validation rejects rather than
normalizes, decodes, trims, changes case, or replaces separators, so it cannot
change a tree byte, `FileID`, or ObjectID.

All ratified v1 profiles also reject C0/DEL controls and reserve a top-level or
nested segment exactly named `.ogvcs` for owner-bound workspace metadata.
Portable/Windows paths reject `< > : " \\ | ? *`, trailing dot/space, and the
Win32 device basenames `CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`, and
the documented superscript-digit forms, including before any extension.
Portable/macOS paths reject colon to avoid legacy/display API ambiguity.

## Case mode and keys

Repository creation records exactly one immutable case mode:

- `case-sensitive`: the repository collision key uses the original NFC scalar
  sequence;
- `case-folded`: it uses the complete Unicode 16.0.0 default case fold (`C` and
  `F`, not `S` or Turkic `T`) from the package's pinned `CaseFolding.txt`.

Case folding is context- and locale-independent. It is applied code point by
code point. No post-fold normalization is performed; comparison is the binary
UTF-8 sequence of the resulting scalars. Original NFC spelling remains the
display value. Keys length-prefix each segment, preserving boundaries.

Every path also has a platform key. Portable, Windows, and macOS v1 use the
folded key conservatively; Linux v1 uses exact NFC. A collision under either
the repository key or platform key is `PATH_COLLISION`. Collision detection is
directory/path complete and cannot depend on native enumeration order.
Caller-supplied diagnostic IDs use only ASCII letters, digits, `.`, `_`, `:`,
or `-` and are limited to 256 characters, so collision errors never disclose or
accidentally reinterpret a path. Materialization hierarchy validation is a
two-pass closed-set check and is independent of whether a child or its parent
appears first.

## Profiles and limits

The four `path.opengamevcs/*@1` profiles are immutable ratified assignments.
All select the OGVCS-002 maxima of 255 UTF-8 bytes and 255 UTF-16 code units per
segment, 4,096 joined UTF-8 bytes and UTF-16 units, and 256 segments. The
UTF-16 ceilings are operational platform bounds, not canonical object fields.
The one-million-entry tree maximum remains OGVCS-002-owned and cannot be raised
or lowered by these profiles.

An implementation may apply a smaller configured resource budget, but it must
report `LIMIT_EXCEEDED` and cannot reinterpret the profile. A new case mapping,
rule, or maximum requires a new profile major and repository migration.
