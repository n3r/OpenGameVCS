# OpenGameVCS PRD system

This directory is the execution backlog for the OpenGameVCS proposal in [the market analysis](../GAME_DEV_VCS_ANALYSIS.md).

All implementation PRDs must conform to the system boundaries and invariants in [the architecture baseline](../architecture.md). If a PRD needs to change an invariant, persistence contract, public protocol, or trust boundary, the architecture and affected PRDs must be reconciled through an ADR before development continues.

## Directory contract

- [`todo/`](todo/) contains approved or proposed work that is not yet complete.
- [`done/`](done/) contains completed PRDs together with implementation evidence.
- [`ROADMAP.md`](ROADMAP.md) defines ordering, dependencies, release gates, and current portfolio status.
- [`../architecture.md`](../architecture.md) defines the shared technical model and constraints that independently developed PRDs must preserve.
- [`TEMPLATE.md`](TEMPLATE.md) is the required shape for new PRDs; it is not itself a PRD.
- [`validate-roadmap.mjs`](validate-roadmap.mjs) checks lifecycle placement, exact document structure, metadata, links, requirement IDs, release ordering, done-dependency closure, contract references, completion evidence, and the dependency graph without external packages.

The folder is the source of truth for status. A dashboard may index it, but must not override it.

## One PRD, one independently delivered change

Each PRD is developed separately:

1. Use one implementation branch/worktree and one review stream for one PRD ID.
2. Do not place implementation for unrelated PRD IDs in the same change.
3. Depend only on completed PRDs or on a versioned interface explicitly published by a dependency.
4. Hide incomplete user-facing behavior behind a disabled-by-default feature flag.
5. If a PRD becomes too large to review or release independently, split it before implementation and update the roadmap.
6. A shared refactor may be extracted into its own PRD; it must not be smuggled into a feature PRD.

`Depends on` lists direct predecessors only. `Blocks` is the exact inverse list of direct dependents; transitive relationships belong in `ROADMAP.md`, not either header. Any dependency edit must update both affected PRDs and the roadmap in the same change.

Every PRD must produce a concrete version-controlled implementation artifact: a service, client, library, CLI, plugin, deployable configuration/package, or executable verification tool with tests. A specification may be part of that artifact, but a PRD cannot consist only of research, recruiting, interviews, procurement, legal work, governance, certification decisions, or partner coordination. Those are program prerequisites recorded in `ROADMAP.md`, outside `todo` and `done`.

“Separately” does not mean “without integration.” Every PRD names its inputs, outputs, dependencies, and release gate. Contract tests are required where another PRD consumes its interface.

## Lifecycle

1. **Todo:** file exists in `prd/todo`, with scope and acceptance criteria complete enough to estimate.
2. **In development:** file remains in `prd/todo`; set `Status: In development`, name the owner, and link the implementation change.
3. **Validation:** implementation is merged behind any required flag; acceptance evidence is being collected.
4. **Done:** all acceptance criteria and release requirements pass. Fill in `Completion evidence`, set `Status: Done`, and move the same file to `prd/done` in the completion change.

Pausing work changes the status to `Todo` or `Blocked`; it never moves the file to `done`.

## Validation

Run this from the repository root before any PRD or roadmap change:

```sh
node prd/validate-roadmap.mjs
node --test prd/validate-roadmap.test.mjs
```

Both commands must pass in the same change that adds, moves, completes, reprioritizes, rewires, or changes validation of a PRD.

## Definition of ready

A PRD may enter development only when:

- its problem, user outcome, in-scope behavior, and non-goals are explicit;
- its concrete software/tooling artifact and bounded development sequence are explicit;
- dependencies are done or an approved versioned contract is available;
- security, durability, compatibility, and observability implications are addressed;
- acceptance criteria are objective and testable;
- rollout and rollback are described;
- there are no unresolved decisions that would materially change architecture or user behavior.

## Definition of done

A PRD moves to `done` only when:

- every acceptance criterion has durable evidence;
- every acceptance criterion and completion-evidence category links to its durable change, test, review, runbook, or rollout record; placeholders and manual assertions do not count;
- unit, integration, contract, fault, security, and performance tests required by the PRD pass;
- documentation, upgrade notes, metrics, alerts, and operational runbooks are merged;
- default behavior is safe for the release gate, or the feature remains explicitly experimental and disabled;
- rollback or data recovery has been exercised where state or formats change;
- no P0/P1 defect remains open against the PRD;
- the implementation and evidence links are recorded in the PRD.

## Change control

- PRD IDs and filenames are immutable after implementation begins.
- Requirements use stable IDs such as `OGVCS-010-FR-03`; do not renumber them after review.
- Scope changes that alter persistence, protocol, security boundaries, compatibility, or user workflow require an architecture decision record and PRD review.
- Moving a PRD between releases requires updating `ROADMAP.md` and every affected dependency.
- Dependency changes must keep `Depends on`, inverse `Blocks`, and the roadmap table consistent and acyclic.
- A dependency must be in the same or an earlier release, and a PRD cannot move to `done` until every direct dependency is also in `done`.
- A completed PRD may be amended only by a new PRD. Historical completion evidence is not rewritten.

## Priority meanings

- **P0:** release gate cannot pass without it.
- **P1:** important for the intended release, but the release can proceed with an explicit limitation.
- **P2:** planned follow-up or ecosystem expansion.
