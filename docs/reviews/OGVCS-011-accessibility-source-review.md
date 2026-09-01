# OGVCS-011 bounded CLI accessibility source review

**Reviewed integration baseline:** `64988fe5461c12a6efcafef8ebc8649e9c0c73ec`

**Acceptance criterion:** OGVCS-011-AC-05

**Verdict:** bounded source/process evidence; OGVCS-011 remains Todo.

## Reviewed surface

After cancellation signal-handler installation, ordinary command outcomes use
one plain human rendering path. Success is a single `ok[CODE]: message` line on
stdout. Failure is an `error[CODE]: message` line followed by a
`Next step: action` line on stderr. The semantic code, explicit error label,
and explicit next-step label carry meaning without color. There are no prompts,
spinners, cursor controls, hyperlinks, terminal-width branches, or ANSI/color
dependencies in this ordinary result path.

The existing versioned machine result remains unchanged for ordinary outcomes:
one JSON object on stdout and empty stderr for success and failure. The
accessibility tranche does not add fields, codes, exit classes, protocol
behavior, or terminal detection.

Signal-handler installation failure remains a separate startup-fatal branch
before format resolution. Its fixed error and next-step text is bounded,
two-line, color-free stderr with an unavailable exit, but it does not emit a
machine JSON envelope. The evidence does not claim ordinary machine stream
semantics for that startup path.

## Executable evidence

The native process contract and hermetic installed-artifact gate exercise
stdout and stderr through pipes with no interactive input. They require exact
byte equality for human success, human failure, and machine failure across:

- no terminal decoration variables;
- `TERM=dumb` with `NO_COLOR=1`;
- an xterm/truecolor environment with force-color hints; and
- contradictory `NO_COLOR` and force-color hints.

The checks reject ANSI escapes, carriage returns, control characters, empty or
unlabeled lines, unexpected line counts, reordered error/next-step text, and
lines above the 384-byte implementation ceiling. A public-route failure is
also repeated in human mode with hostile terminal variables while canary root,
repository locator, and credential values remain absent and no workspace is
created. Exact machine bytes and stdout/stderr separation for the exercised
ordinary outcomes must not drift under the same environments.

The crate has no color, terminal detection, or progress-rendering dependency.
The evidence therefore tests both the source boundary and the ordinary release
binary after it has been packaged, unpacked, copied into an otherwise empty
runtime root, and detached from the build/source trees.

## Nonclaims and remaining release evidence

This review does not claim a screen-reader user study, shell-specific wrapping
policy, localized text, an interactive TTY/PTY matrix, signed package behavior,
or hosted Linux/macOS/Windows results for the exact candidate. It also does not
close the existing public-route, remote E2E, receipt-proof, or later-command
residuals. Those completion conditions remain unchanged, so this tranche must
not move OGVCS-011 to Done.
