# Untrusted tool sandbox contract v1

## Scope

This contract applies to repository hooks, semantic merge drivers, import
parsers, preview/thumbnail converters, and any tool processing repository-
supplied bytes or code. It defines the minimum containment request and testable
postconditions. It does not claim that a language-level wrapper alone is a
sandbox.

## Required enforcement

The trusted launcher, outside the hostile process, MUST enforce the selected
entry from `registries/sandbox-profiles.json`:

- a fresh process/container identity and isolated working directory;
- only explicitly declared immutable inputs, mounted/read through read-only
  handles; no ambient repository, user-home, host, socket, device, or credential
  path;
- an isolated scratch namespace capped at 1 GiB and destroyed after result
  validation;
- network default deny, including loopback, metadata endpoints, DNS, inherited
  sockets, and namespace escape;
- no session, service, acquisition, transfer, cloud, signing, KMS, SSH, or
  package-registry credential in arguments, files, environment, handles, or
  process ancestry;
- pinned and signature-verified runtime/tool bytes;
- hard ceilings of 30 seconds CPU, 60 seconds elapsed, 512 MiB resident memory,
  256 MiB output, 10,000 output/fanout records, and eight processes; and
- process-tree termination on cancellation or any ceiling, including descendants
  that close or detach inherited handles.

Platforms may use stricter profiles. A platform unable to enforce a required
property denies with `DENY_SANDBOX_REQUIREMENTS`; it does not run with a warning.

## Acquisition/parser separation

Git/LFS and Perforce import acquisition may need source credentials and network.
That acquisition runs in a separate minimal broker that fetches bounded immutable
inputs into staging. The parser sandbox receives only the staged declared input,
no broker credential, and no network. Parser output cannot select a target
repository/ref or publish authority directly.

## Output boundary

Tool output is untrusted. The trusted caller checks byte/count/schema/path/object
limits, canonical form, declared input/output bindings, and operation-specific
semantics before storing it. Publication uses the normal authorization and
transaction path. A successful process exit, valid signature on the tool binary,
or output digest does not make derived data authoritative.

No partial output becomes trusted after timeout, kill, overflow, cancellation,
or validation failure. Logs are subject to the same output cap and are redacted
before any diagnostic bundle.

## Conformance tests

A sandbox implementation must demonstrate, with disposable fixtures:

- outbound TCP/UDP/DNS/loopback/metadata access is denied;
- undeclared host, repository, home, device, and credential paths are absent;
- declared inputs cannot be changed and scratch cannot escape its root;
- CPU, elapsed, resident-memory, output, fanout, and process limits terminate the
  whole process tree;
- signals, child processes, symlinks/reparse points, inherited handles, and
  race/reopen attempts do not escape confinement;
- credentials are absent from environment, files, arguments, handles, and logs;
  and
- invalid or partial output is rejected and never published.

The contract vectors validate the requested profile and negative outcome. Future
platform runners owned by OGVCS-005/020/026/029/031/039/045 must provide the
OS-level escape tests; the reference JavaScript runner intentionally does not
pretend to supply kernel isolation.
