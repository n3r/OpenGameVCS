# Application-neutral transfer probe

## Carrier

The probe defines an identity-coded half-open byte range `[startOffset,
endOffsetExclusive)`, a strong representation validator, RFC 9530 content
digest, interruption, resume, and explicit completion. The end may be omitted
only where the carrier can bound the remaining representation before reading;
the requested and actual range never exceed maxTransferRangeBytes. Resume
requires the same strong validator. A validator or digest change rejects the
assembled representation rather than mixing generations.

TransferProbeResult always satisfies
`0 <= acceptedStart <= acceptedEndExclusive <= totalBytes`. `complete` is the
only terminal state and requires acceptedEndExclusive equal totalBytes.
`partial` is nonterminal with nonempty accepted progress strictly before total;
`interrupted` is nonterminal and also ends strictly before total, but may make
zero progress (acceptedStart equal acceptedEndExclusive). `rejected` is
nonterminal, accepts no bytes (start equals end), and requires a registered safe
problem. Complete, partial, and interrupted results forbid a problem.

## HTTP Range carrier

A bounded half-open probe range maps to one request field: `Range:
bytes=start-(endOffsetExclusive-1)`, or `Range: bytes=start-` when the
semantic end is omitted. A request without Range returns 200. Every satisfiable
Range request returns 206 and exactly one `Content-Range: bytes
start-endInclusive/total`; an unsatisfied range returns 416 with exactly one
`Content-Range: bytes */total`, an empty body, and neither `Content-Digest`
nor `ETag`. Resume sends `If-Range` with the exact quoted strong ETag. Weak
or mismatched validators reject.

For a request without Range, `endOffsetExclusive` may be absent. The 200
response still carries the complete representation and binds its total byte
length, validator, and content digest; omission is not interpreted as an empty
or partial body.

Field names are received ASCII-case-insensitively and duplicates are rejected
after lowercase normalization. Response `Content-Length` is the canonical
decimal exact body length, including zero for 416. Content coding remains
identity. The only response statuses on this carrier are 200, 206, and 416; any
other status is `PROTOCOL_MALFORMED` before validator-presence or range-semantic
checks. Malformed fields, inclusive/exclusive off-by-one conversions, total
mismatches, wrong 200/206/416 state, duplicate authority fields, and length
mismatches fail before accepting representation bytes. This carrier defines no
URL, route, session, or pack layout.

TransferProbe fields `validatorTag`, `expectedSha256`, and TransferProbeResult
fields `validatorTag`, `contentSha256` are semantic values, not literal HTTP
field syntax. At the HTTP/1.1 boundary a validator tag is encoded as a quoted
RFC 9110 strong ETag and a SHA-256 digest is encoded as RFC 9530
`sha-256=:BASE64(32 digest bytes):`. Receivers parse those exact forms back to
the semantic values before comparison. Every successful 200/206 carries exactly
one canonical strong `ETag` and one canonical `Content-Digest`. The digest is
SHA-256 of the decoded bounded `responseBodyHex`; `Content-Length` equals that
decoded byte length. On the HTTP Range conformance route, a present
`expectedSha256` is the expected response-body digest. A present
`validatorTag` is compared with the decoded ETag; otherwise the decoded ETag is
returned as the response validator. The accepted trace binds both decoded
values. Unquoted or weak ETags, hex in Content-Digest, another digest algorithm,
missing or duplicated fields, and body/digest mismatches do not silently coerce.

Before inspecting the grant carrier or invoking OGVCS-003, the receiver first
requires the public TransferProbe schemaVersion
`ogvcs.protocol/transfer-probe/v1`, then projects every non-grant field into
TransferProbeNonGrantInput with its distinct projection selector
`ogvcs.protocol/transfer-probe-non-grant-input/v1`. It validates that closed shape,
range ordering, and resume rule. The projection selector is never accepted as a
public TransferProbe selector. A positive startOffset
requires validatorTag and otherwise returns TRANSFER_VALIDATOR_MISMATCH. Shape
failures return PROTOCOL_MALFORMED and reversed/empty half-open ranges return
TRANSFER_RANGE_INVALID before any grant-derived distinction. Only after that
preflight does a malformed grant map to TRANSFER_GRANT_INVALID and a valid grant
reach the pinned verifier.

The hard or configured `maxGrantBytes` ceiling measures only the decoded bytes
of `CompactTransferGrant.envelope`, never the canonical byte size of the compact
grant wrapper. An envelope at or below that ceiling proceeds to closed compact-
grant shape validation; a malformed wrapper then returns TRANSFER_GRANT_INVALID,
while PROTOCOL_LIMIT_EXCEEDED is reserved for an envelope that exceeds the
ceiling.

The Authorization carrier holds an opaque canonical OGVCS-003 envelope. At
this boundary it must represent one request-root grant and report
explicitObjectCount zero. Object-ID lists and grants in query strings are
forbidden. The authorization implementation still verifies issuer, key
generation, authority epoch, principal/repository scope, operation, audience,
expiry, request root, and replay rules; protocol code cannot reinterpret or
broaden the grant. Each public conformance TransferCaseInput carries the actual
opaque envelope, bounded authorization context, and public verification JWK.
The context and JWK are generic transport-bounded JSON carriers passed unchanged
to the pinned OGVCS-003 verifier; this contract deliberately does not duplicate
their semantic schema or maxima. Predecessor case identifiers, expected
outcomes, vector paths, and digests remain harness-only provenance and never
reach an adapter. Context-mismatch witnesses reuse the authenticated
valid-request-root envelope and project only the predecessor case's relevant
verification-context member. The replay witness is a fixed protocol-owned,
conformance-only envelope derived once from those request-root claims with a
distinct nonce and single-use replay policy and signed through the exact
predecessor conformance signer. Runtime protocol code never signs or issues
grants. The two explicit-object predecessor cases remain executable compact-
carrier rejection witnesses. RFC 9530 validates transferred representation
bytes and does not replace OGVCS-002 object identity validation.

## Ownership boundary

This profile is a synthetic application-neutral conformance probe. It defines
no production URL, object route, upload resource/session, multipart behavior,
pack layout, compression, storage placement, availability promise, or retry
queue. OGVCS-008 owns those choices and must preserve these carrier invariants.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
