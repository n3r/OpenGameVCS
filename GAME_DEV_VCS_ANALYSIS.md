# Version control for game-development studios

## Market analysis and proposal for an open-source alternative

**Research date:** 14 August 2026  
**Scope:** source code, original art, engine-native assets, configuration, and the history needed to reproduce a game project. Build outputs and disposable derived data are treated separately.  
**Evidence policy:** capability claims are linked to first-party product or project documentation. Vendor scale claims are not treated as comparable benchmarks. Prices and free-tier limits are point-in-time facts and should be rechecked before procurement.

---

## Executive conclusion

There is no current open-source VCS that is a complete, first-class replacement for Perforce P4 across a large game studio.

- **Perforce P4** remains the safest established choice for very large, asset-heavy, geographically distributed productions. It combines selective workspaces, authoritative exclusive checkout, mature engine integration, fine-grained permissions, streams, proxies, and edge servers. The tradeoffs are proprietary licensing, operational complexity, central-service dependence, and expensive exit paths.
- **Git + Git LFS** is the best default for code-heavy indie and small-to-medium teams that value open tooling and the Git ecosystem. It becomes increasingly awkward when one repository contains millions of paths, terabytes of binary history, many nontechnical users, or strict cross-branch locking requirements.
- **Unity Version Control (UVCS, formerly Plastic SCM)** has the most coherent combined programmer/artist workflow among the established alternatives: distributed and centralized modes, Gluon partial workspaces, and branch-aware Smart Locks. It is proprietary and creates a different form of vendor dependence.
- **Apache Subversion** is the strongest fully open-source, lock-first option available today. It has centralized semantics, path-based authorization, and repository locks, but lacks the modern large-asset transport, artist experience, branch workflow, geographic architecture, and integration ecosystem expected by a contemporary large studio.
- **Mercurial with large-file extensions** is technically viable for some teams but lacks a maintained, native locking story and has a much smaller game-tool ecosystem. It is not the strongest foundation for a new studio deployment.
- **Diversion** is a credible newer game-focused proprietary entrant with large-asset workflows, engine plugins, and hard/soft locks. Its shorter operating history, smaller ecosystem, and proprietary service model make a production bakeoff and an explicit exit test essential.

The proposed open-source system should therefore **not be a thin GUI over Git LFS** and should not attempt to clone every Perforce command. It should be a hybrid, game-specific VCS with:

1. server-authoritative atomic snapshots, permissions, and locks;
2. cheap metadata branches and local pending changes for programmer workflows;
3. content-defined chunking, deduplication, resumable transfer, regional caches, and on-demand workspace materialization;
4. branch-aware hard locks plus advisory edit intent for nonmergeable assets;
5. an artist-first desktop client and native Unreal/Unity integrations;
6. open protocols, self-hosting, complete export, and neutral governance;
7. a Git/LFS bridge so studios can preserve their code-review and CI ecosystem during adoption.

This report uses **OpenGameVCS** as a working name only.

---

## 1. Why game version control is a distinct problem

A game repository is not merely a software repository with a few large files. It joins several workloads with conflicting needs.

| Persona | Daily job | VCS behavior that matters |
|---|---|---|
| Programmer | Edit, branch, merge, review, bisect, automate | Fast local operations, cheap branches, reliable three-way merge, IDE and CI integration |
| Artist / animator / audio designer | Find an asset, reserve it, edit in a DCC tool, preview, submit | Visual UI, no command-line requirement, automatic locking, thumbnails/diffs, no full-depot download |
| Level / technical designer | Edit both structured text and opaque engine packages | Lock-or-merge policy by asset type, engine-aware status, dependency context |
| Build farm | Reproduce an immutable project state repeatedly | Snapshot IDs, high-throughput sparse sync, shared cache, service identities, no per-agent workspace administration |
| Producer / reviewer | Inspect a coherent change across code and assets | Shelves/reviews, visual previews, audit trail, approval policy |
| Administrator | Protect IP and keep production available | Path permissions, identity federation, audit, backup verification, capacity controls, observability, disaster recovery |

### 1.1 The files are large, numerous, and often nonmergeable

Game depots contain source code and text metadata alongside textures, audio, video, meshes, mocap, Photoshop files, Blender/Maya scenes, and engine packages. Many of those formats cannot be meaningfully line-merged. A conflict discovered only at push time can discard hours or days of creative work.

This makes **coordination before edit** a correctness feature, not merely a convenience. Unreal's own source-control workflow presents checkout as locking an asset for edit, and Epic recommends source control at the start of a project. Epic currently lists Perforce, Git with Git LFS, Subversion, and Diversion integrations, while noting that many of its scaling workflows revolve around Perforce ([Epic: scaling an Unreal team](https://dev.epicgames.com/documentation/en-us/unreal-engine/resources-for-scaling-your-unreal-engine-team)).

### 1.2 A full local copy is often wasteful

The relevant working set for a character artist, audio designer, gameplay programmer, and build machine is different. Epic describes long sync times, high local disk use, poor experience on slow links, and duplicate copies as projects grow; Unreal Virtual Assets address this by separating bulk payload from metadata and fetching payloads on demand ([Epic: Virtual Assets overview](https://dev.epicgames.com/documentation/unreal-engine/overview-of-virtual-assets-in-unreal-engine)). A general-purpose game VCS needs the same property below the engine layer.

### 1.3 The repository and the asset graph are related but not identical

A source asset, its engine import metadata, and related sidecar files may need to change atomically. Unity, for example, can serialize scenes as text to make merges possible and ships `UnityYAMLMerge` for semantically aware scene and prefab merging ([Unity: asset serialization](https://docs.unity3d.com/6000.0/Documentation/Manual/class-EditorManager.html), [Unity: Smart Merge](https://docs.unity3d.com/6000.0/Documentation/Manual/SmartMerge.html)). Unreal reduces level contention with One File Per Actor by putting actor instances in separate files ([Epic: One File Per Actor](https://dev.epicgames.com/documentation/unreal-engine/one-file-per-actor-in-unreal-engine)).

The VCS should use these engine capabilities, but it cannot assume every binary is mergeable or become a replacement for the engine's dependency database.

### 1.4 Global teams need locality without split authority

Bulk payload should be served near the user, while branch heads, locks, permissions, and audit events need a consistent authority. Perforce demonstrates this split: proxies cache file revisions near users, while commit/edge deployments move more workspace work close to a site ([P4 Proxy](https://help.perforce.com/helix-core/server-apps/p4sag/2024.2/Content/P4SAG/chapter.proxy.html), [P4 deployment architecture](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/deployment-architecture.html)). A new design should retain the principle but reduce the number of stateful servers an administrator must protect.

### 1.5 “Open source” does not mean “zero cost”

Storage, egress, compute, backups, observability, upgrades, support, and administrator time remain real costs. The strategic advantages of an open system are control of the software and data, competitive hosting and support, inspectable formats and protocols, the right to modify, and a credible exit path—not free infrastructure.

---

## 2. Evaluation criteria

The following are requirements, not optional polish.

### 2.1 Functional requirements

1. **Large assets:** multi-gigabyte files, terabyte-scale history, resumable parallel transfer, integrity checking, and storage/transfer deduplication.
2. **Very large trees:** responsive status and sync with hundreds of thousands to millions of paths.
3. **Selective workspaces:** include/exclude rules and on-demand hydration without downloading irrelevant history or payload.
4. **Atomic changes:** code, assets, deletes, moves, and sidecars publish as one indivisible change.
5. **Conflict policy by content type:** three-way merge for text/structured formats; hard locks for opaque binaries; advisory intent when prevention is too restrictive.
6. **Branch-aware coordination:** a lock must account for the branch or integration destination on which two edits will eventually collide.
7. **Local work:** local diff, checkpoint, revert, and offline work for mergeable content. A hard lock necessarily requires a reachable authority.
8. **Review:** shelves or proposed changes with code diff, image/audio/3D preview, comments, CI status, and approval rules.
9. **Engine and DCC integration:** Unreal and Unity first; a stable SDK for Godot, Blender, Maya, Photoshop, and custom tools.
10. **Automation:** deterministic snapshot sync, service accounts, webhooks/events, API/CLI stability, and cache-friendly build agents.

### 2.2 Nonfunctional requirements

1. **Security:** OIDC/SAML integration, least privilege, path-level read/write rules, no metadata leakage from hidden paths, short-lived credentials, and an immutable audit trail.
2. **Durability:** checksummed immutable payload, continuous verification, documented backup/restore, and tested disaster recovery.
3. **Geographic performance:** regional read-through caches and transfers whose cost is proportional to missing content.
4. **Operational simplicity:** a small deployment must be simple; HA and global deployments must be composable rather than mandatory.
5. **Portability:** published file/protocol formats, a full-fidelity export, and no license check that can make existing data unavailable.
6. **Cross-platform correctness:** Windows/macOS/Linux differences in case, Unicode, executable bits, symlinks, long paths, and file watching.
7. **Observability:** OpenTelemetry-compatible metrics/traces/logs, capacity forecasts, lock diagnostics, transfer accounting, and repair tools.

### 2.3 Evidence caveat

The comparison below says whether a capability is documented and how coherently it fits the workflow. It is not a normalized performance benchmark. A vendor's “millions of files” claim and another vendor's “petabytes” claim use different data, hardware, topology, cache state, and operation definitions. Procurement should use the bakeoff in section 8.

---

## 3. Existing systems: strengths and weaknesses

### 3.1 Perforce P4 (Helix Core)

**Model.** Primarily centralized, with server-managed depots, workspace views and have-lists, atomic changelists, streams, exclusive-open file types, and optional proxy/replica/edge topology. A workspace can contain a subset of the repository ([P4 basic architecture](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/intro.architecture.html)); views can explicitly exclude paths ([P4 workspace views](https://help.perforce.com/helix-core/server-apps/p4guide/current/Content/P4Guide/configuration.workspace_view.exclude.html)).

**Pros**

- First-class handling of large binary depots and selective workspaces; clients do not need a distributed copy of all history.
- Server-enforced exclusive checkout through the `+l` file type. Unlike a submit-time lock, exclusive-open prevents a second user from opening the file for edit ([P4 exclusive checkout](https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/P4Guide/resolve.lock.exclusive.html)).
- Typemap rules can automatically make engine and DCC formats lockable and can set revision-retention policy by file type ([P4 typemap guidance](https://help.perforce.com/helix-core/cloud/current/Content/Cloud/admin-set-up-typemap.html)).
- Streams define hierarchical branches, views, and permitted change flow ([P4 streams](https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/P4Guide/streams.configure.html)).
- Mature Unreal/Unity integrations, visual client, APIs, fine-grained permissions, audit, and a large game-industry knowledge base.
- P4 Proxy caches revisions near remote teams. Edge servers can keep workspace and work-in-progress metadata near a site, reducing central load and latency.
- Mature replication, failover, checkpoint, journal, and recovery mechanisms.

**Cons**

- Proprietary licensing and server/client implementation create commercial and technical lock-in. The current free tier is limited to five users and twenty workspaces; the managed cloud offer is currently advertised at USD 39/user/month with 64 GiB included, while larger self-hosted plans require a quote ([P4 pricing, checked 2026-08-14](https://www.perforce.com/resources/vcs/helix-core-pricing)).
- Administration is a specialty. A server owns metadata databases, archive content, and logs; reliable recovery requires coordinated checkpoints, journals, archive backups, and restore practice ([P4 disaster recovery](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/secure-prepare-disaster-recover.html)). Commit/edge deployments add stateful nodes and separate backup obligations.
- The simple centralized workflow is approachable, but streams, views, typemaps, protections, edge placement, shelves, and integration history create a substantial configuration and training surface.
- Central authority is a dependency for ordinary submit and lock operations. Even in a commit/edge topology, global exclusive locks communicate with the commit server and can incur WAN latency ([P4 commit/edge considerations](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/commit-edge-managing.html)).
- Branching is capable but heavier than the local branch/commit workflow programmers expect from Git.
- Per-seat cost is only part of TCO; infrastructure, storage, backups, monitoring, upgrades, and specialist administration remain.

**Best fit.** Large or global, asset-heavy productions that need proven workflows and can fund licenses and VCS operations. Particularly strong for Unreal pipelines already built around P4.

### 3.2 Git + Git LFS

**Model.** Git provides distributed, immutable, content-addressed commits, trees, and blobs. Git LFS replaces selected large files in Git history with small pointers and transfers the corresponding content through a separate LFS service ([Git data model](https://git-scm.com/docs/gitdatamodel.html), [Git LFS specification](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md)). Git and Git LFS are open source; hosting can be commercial or self-managed.

**Pros**

- Ubiquitous developer workflow, tooling, education, IDE support, code review, CI/CD, and automation.
- Fast local history and branching for normal source code; programmers can commit, diff, inspect history, and branch while disconnected.
- Open implementation and protocols with many hosting choices. Git is GPLv2-covered ([Git source project](https://github.com/git/git)); Git LFS is an open-source extension and specification ([Git LFS](https://git-lfs.com/)).
- LFS keeps large payload outside the normal Git object database, reducing ordinary clone/fetch volume when correctly configured.
- A standard LFS locking API can create, list, verify, and delete locks. `git lfs track --lockable` can make matching working-copy files read-only until locked ([Git LFS locking API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md), [Git LFS lockable files](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-track.adoc)).
- Git partial clone, sparse checkout, and Scalar improve large-repository behavior. Scalar applies opinionated configuration and background maintenance for large Git repositories ([Git partial clone](https://git-scm.com/docs/git-clone.html), [Git sparse checkout](https://git-scm.com/docs/git-sparse-checkout.html), [Scalar](https://git-scm.com/docs/scalar/2.53.0.html)).
- A completely open self-hosted stack is possible. Forgejo, for example, supports LFS locks, local or S3-compatible LFS storage, and configurable file limits ([Forgejo configuration](https://forgejo.org/docs/latest/admin/config-cheat-sheet/), [Forgejo storage](https://forgejo.org/docs/v15.0/admin/setup/storage/)).

**Cons**

- Git and LFS are two coordinated data planes. Correct behavior depends on client installation, filters, `.gitattributes`, hooks, and server support. A misconfigured client can commit pointer mistakes or normal Git blobs; the official FAQ recommends CI checks for this class of failure ([Git LFS FAQ](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-faq.adoc)).
- Standard LFS identifies and transfers whole file objects. A one-byte modification creates a new file object; the protocol does not promise content-defined chunk reuse or delta transfer. A host may optimize internally, but a studio cannot rely on that property from LFS alone.
- LFS tracking is pattern-based and cannot automatically track all files above a size threshold. Existing history requires an explicit migration and often a history rewrite ([Git LFS FAQ: file-size tracking and migration](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-faq.adoc)).
- The published locking API explicitly describes its first version as the simplest, single-branch use case. Client-side verification can be disabled or unsupported, so robust enforcement also depends on the server and push path ([Git LFS locking API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md), [lock verification configuration](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc)).
- Lock acquisition is not naturally coupled to opening an asset in every editor. Artist experience depends on third-party clients and plugins.
- Sparse checkout and partial clone improve payload selection but expose complex Git behavior; the sparse-checkout documentation still describes behavioral caveats and commands that may fetch missing objects as a side effect ([Git sparse-checkout design](https://git-scm.com/docs/sparse-checkout)).
- Git repository authorization is not part of Git's object model. Common hosts grant roles at repository scope; path-sensitive read access is difficult because commits and trees connect the repository graph. GitHub, for example, documents repository-level roles rather than per-folder roles ([GitHub repository roles](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization)).
- A large LFS payload is separate, but the commit/tree/pointer graph and index still grow with path count and history. Millions of files remain a different problem from a repository with a few very large files.
- Hosted storage, bandwidth, retention, and maximum-file limits vary by provider. Open client software does not eliminate hosting charges or quotas.

**Best fit.** Code-heavy or moderately asset-heavy teams with strong Git knowledge, good automation discipline, repository boundaries that match access boundaries, and manageable working sets. It is a strong present-day choice for many indie and AA teams, not a universal AAA asset depot.

### 3.3 Unity Version Control (Plastic SCM)

**Model.** A proprietary VCS supporting centralized and distributed workflows. The full Plastic client targets programmers; Gluon provides a selective, centralized-style workflow for artists. Unity describes UVCS as engine-agnostic despite its Unity ownership ([Unity UVCS quick start](https://learn.unity.com/tutorial/unity-version-control-guide)).

**Pros**

- Coherent support for code and large binary assets in one repository.
- Gluon is explicitly designed for artists who work on nonmergeable files, want locks, and do not want to download a huge repository. Users select the paths to materialize ([Unity: Gluon](https://docs.unity.com/unity-version-control/gluon/gluon), [Gluon workspace configuration](https://docs.unity.com/ugs/en-us/manual/devops/manual/gluon/configure-workspace)).
- Strong visual branch and merge workflow for programmers, with centralized and distributed modes.
- Smart Locks understand a destination branch and retained state, preventing an old revision from being locked when a newer relevant revision exists on another branch ([Unity: Smart Locks](https://docs.unity.com/en-us/unity-version-control/smart-locks)). This is materially stronger than a path-only, single-branch lock.
- Artist-oriented GUI, Unity integration, Unreal support, image diff, and file history.
- Cloud service reduces administrator effort; an on-premises product also exists under subscription terms ([Unity DevOps terms](https://unity.com/de/legal/terms-of-service/devops/)).

**Cons**

- Proprietary server, clients, formats, pricing, and roadmap; adopting it exchanges Perforce dependence for Unity dependence.
- Cloud usage and seats are metered. Unity's current free plan locks a project into read mode after a limit is exceeded and documents deletion of cloud data after thirty days if the plan is not upgraded ([Unity DevOps free plan](https://docs.unity.com/en-us/devops/pricing/free-plan)). Exact allowances and rates are changeable and must be checked for the intended region and plan.
- Smart Lock semantics are powerful but add concepts—destination branches, retained locks, lock rules—that teams must understand.
- Unity documents limits around Smart Locks and replica repositories: locks do not travel across replica repositories, and replicas may hold newer revisions ([Unity: Smart Locks technical considerations](https://docs.unity.com/en-us/unity-version-control/smart-locks)).
- The ecosystem, administrator labor pool, and third-party integrations are smaller than Git's and, in many AAA environments, Perforce's.
- Non-Unity studios must assess product direction and integration quality independently rather than infer it from the Unity branding.

**Best fit.** Mixed programmer/artist teams, especially Unity studios, wanting a modern managed experience and willing to accept a proprietary platform.

### 3.4 Apache Subversion

**Model.** Mature open-source centralized version control under Apache License 2.0 ([Apache Subversion](https://subversion.apache.org/), [Subversion licensing](https://subversion.apache.org/docs/community-guide/general)). The server owns canonical history; working copies contain selected repository paths.

**Pros**

- Simple centralized mental model with atomic repository revisions.
- Native repository locks; another user cannot commit to a locked path unless the lock is broken ([Subversion `svn lock`](https://svnbook.red-bean.com/en/1.8/svn.ref.svn.c.lock.html)).
- Fine-grained path and even file authorization is built into the server model ([Subversion path-based authorization](https://svnbook.red-bean.com/en/1.8/svn.serverconfig.pathbasedauthz.html)).
- Partial checkout/update is natural; users do not clone all repository history.
- Server-side branches are cheap copies rather than complete duplicated trees ([Subversion branches and cheap copies](https://svnbook.red-bean.com/en/1.8/svn.branchmerge.using.html)).
- Stable, widely understood, fully self-hostable, and directly supported by Unreal's built-in source-control integration.
- No per-user software fee and no proprietary server required.

**Cons**

- No native game-specific artist client comparable to Gluon or a carefully configured P4V workflow.
- Large binary storage is supported, but Subversion does not provide a modern integrated content-defined chunk store, shared local cache, or transparent virtual workspace.
- Conventional centralized deployment is sensitive to WAN latency; geographic caching and edge-write topology are less comprehensive than P4's.
- Branching and merge are capable but less fluid and less aligned with modern code-review ecosystems than Git or UVCS.
- Offline history and local commit workflows are limited by the centralized model.
- Fine-grained authorization has performance and administrative costs; the Subversion book explicitly warns that the server performs more work for path checks.
- The surrounding game-development ecosystem and visible product momentum are smaller than the leading proprietary tools and Git.

**Best fit.** Teams that require a fully open-source, centralized, lock-first system today and can accept a more traditional workflow. It is also a useful migration source and a valuable architectural reference, but not the desired end state.

### 3.5 Mercurial with large-file extensions

**Model.** Open-source distributed VCS. The bundled `largefiles` extension stores hashes in repository metadata and transfers actual content on demand; Mercurial also has an LFS extension/protocol integration ([Mercurial repository requirements and largefiles](https://mercurial-scm.org/missing-requirement)).

**Pros**

- Strong distributed fundamentals, local commits, branching concepts, extensibility, and generally approachable CLI behavior.
- Large-file content can be separated and fetched on demand.
- Open source and self-hostable, with no required per-seat license.
- Proven use in some very large software organizations, although those deployments commonly include organization-specific infrastructure.

**Cons**

- No maintained, first-class exclusive locking workflow suitable for game assets. A 2023 discussion on the project's official mailing list reported no currently maintained lock extension and noted that Git LFS locking was not implemented in Mercurial at that time ([Mercurial locking discussion](https://lists.mercurial-scm.org/pipermail/mercurial/2023-November/106364.html)). This must be revalidated if Mercurial is shortlisted.
- The large-file behavior is extension-dependent and adds a second content path, with similar operational concerns to Git LFS.
- Smaller hosting, review, desktop-client, engine-plugin, and hiring ecosystem than Git.
- Selective clone is primarily revision/ancestry-oriented rather than a native artist workspace over a huge asset tree ([Mercurial clone](https://mercurial-scm.org/help/commands/clone)).
- Choosing Mercurial for a new studio does not provide enough game-specific advantage over Git LFS or SVN to compensate for the ecosystem gap.

**Best fit.** Existing Mercurial organizations with the expertise to build their own asset coordination layer. Not recommended as the default for a new studio.

### 3.6 Diversion

**Model.** Proprietary, cloud-oriented VCS built for game projects and large repositories, with desktop, web, CLI/API, Unreal, and Unity integrations. Enterprise deployment options are advertised for private cloud, on-premises, and hybrid environments.

**Pros**

- Purpose-built large-file and game-engine workflow rather than a large-file sidecar on a code VCS.
- Hard locks prevent another user from committing a locked path; soft locks communicate edit intent. Official docs define hard locks as repository/path scoped and server enforced ([Diversion hard locks](https://docs.diversion.dev/hard-locks)).
- Native Unreal and Unity plugins, code and asset reviews, previews, branching, and modern onboarding.
- Cloud operation can remove much of the server-administration burden.
- Epic now lists Diversion among supported Unreal source-control integrations ([Epic: scaling an Unreal team](https://dev.epicgames.com/documentation/en-us/unreal-engine/resources-for-scaling-your-unreal-engine-team)).
- Migration and Git mirroring are advertised, which can lower trial friction.

**Cons**

- Proprietary service and implementation; hard locks are documented as paid Studio/Enterprise features.
- Newer product with a shorter public production history and smaller administrator/integration ecosystem than P4 or Git.
- Published performance and TCO numbers are vendor claims, not a controlled comparison. They should be validated against the studio's depot and network ([Diversion game-development product page](https://www.diversion.dev/game-development)).
- Cloud-first operation introduces availability, data-residency, egress, pricing, and exit considerations. Enterprise private deployment terms require commercial validation.
- Migration claims do not by themselves prove full fidelity for Perforce integration history, streams, labels, permissions, file types, or custom triggers.

**Best fit.** Teams wanting a managed, modern game-specific workflow and prepared to validate a newer proprietary vendor. It belongs in a bakeoff, not in an untested studio-wide cutover.

### 3.7 Adjacent tools are not complete substitutes

- The detailed shortlist contains systems that satisfy at least two of these screening conditions: a documented large-asset design, authoritative locking, a direct game-engine workflow, or substantial current VCS deployment. It is representative rather than an inventory of every source-control project.
- Artist-friendly Git clients can hide commands and automate LFS locks, but they inherit Git/LFS storage, authorization, branch, and enforcement semantics.
- DVC, git-annex, lakeFS, and data-versioning tools solve valuable large-data problems but do not provide the complete edit/lock/engine/review workflow of a game studio VCS.
- Forgejo, Gitea, GitLab, and GitHub add hosting, permissions, collaboration, and LFS implementations around Git; they do not replace Git's underlying snapshot and repository security model.
- Scalar, Sapling, Jujutsu, and similar projects contain useful ideas for large source trees or developer workflows, but none currently documents the complete game-asset locking, artist client, engine integration, and open large-payload service required here. They are candidates for component reuse, not direct drop-in replacements.
- Fossil, Pijul, and other general-purpose VCS projects remain valuable, but adding a long catalog of tools without a documented game-production fit would imply evidence this analysis does not have.
- Unreal Virtual Assets and Derived Data Cache reduce payload and rebuild cost but do not replace source control. Epic currently requires Perforce for its documented Virtual Assets source-control backend ([Epic: Virtual Assets requirements](https://dev.epicgames.com/documentation/unreal-engine/overview-of-virtual-assets-in-unreal-engine)).
- Asset management/DAM systems add catalog, search, approval, and delivery. They complement rather than replace change history, branches, atomic commits, and reproducible builds.

---

## 4. Comparative view

The ratings are directional assessments of documented workflow fit: **strong**, **adequate**, **weak**, or **gap**. They deliberately do not produce a single numerical winner.

| System | Large assets | Selective workspace | Binary coordination | Code branches / merge | Artist / engine UX | Global topology | Openness / exit | Operations |
|---|---|---|---|---|---|---|---|---|
| P4 | Strong | Strong | Strong, global exclusive-open | Strong, heavier workflow | Strong | Strong, but complex | Weak | Mature, specialist-heavy |
| Git + LFS | Adequate; whole-object LFS | Adequate, complex at extreme scale | Weak-to-adequate; simple LFS locks | Strong | Weak-to-adequate via third parties | Adequate; LFS remains service-dependent | Strong | Flexible, two data planes |
| UVCS | Strong | Strong through Gluon | Strong, branch-aware | Strong | Strong | Adequate-to-strong | Weak | Managed option; proprietary |
| SVN | Adequate | Strong for ordinary partial checkout | Adequate-to-strong path locks | Weak-to-adequate | Adequate in Unreal; otherwise dated | Weak-to-adequate | Strong | Mature and understandable |
| Mercurial + large files | Adequate | Weak for asset-tree selection | Gap in maintained native locking | Strong | Weak | Adequate | Strong | Extension-dependent |
| Diversion | Documented strong; benchmark | Documented strong; benchmark | Strong hard/soft locks | Documented strong; benchmark | Strong | Documented strong; benchmark | Weak | Simple SaaS; newer platform |

### 4.1 Selection guidance for a studio choosing now

| Situation | Practical shortlist | Reason |
|---|---|---|
| Small, code-heavy, Git-experienced team | Git + LFS | Lowest workflow friction and broadest ecosystem; automate configuration checks |
| Small asset-heavy team requiring fully open source | SVN and Git + LFS bakeoff | SVN favors central locks/partial checkout; Git favors code workflow |
| Unity studio with many artists | UVCS and Git + LFS; add P4 at higher scale | Gluon and Smart Locks are unusually well matched to artist work |
| Unreal studio with large binary depot | P4, UVCS, Diversion bakeoff | P4 is the proven baseline; validate newer workflows and exit paths |
| Global AAA production | P4 baseline plus carefully scoped alternatives | Scale, topology, integrations, support, and migration risk dominate license price |
| Sovereign / air-gapped / no proprietary runtime allowed | SVN today; sponsor the proposed open system | No current open system spans the complete desired feature set |

The immediate procurement answer and the strategic open-source answer are different. A shipping game should not wait for a new VCS. The open-source initiative should begin with design partners and production-shadow pilots while studios continue using a proven system.

---

## 5. The unfilled market gap

### 5.1 Problems in proprietary systems

| Problem | Consequence |
|---|---|
| Per-seat licensing and opaque enterprise pricing | Cost rises with contractors, outsourcing, build/service identities, and project peaks |
| Proprietary server, protocol, and metadata | Exit depends on vendor tools and may lose integration history or policy semantics |
| Specialist topology and backup knowledge | Smaller studios either under-operate the service or pay for managed expertise |
| Vendor roadmap and account dependency | Terms, packaging, platform direction, and end-of-life decisions are outside studio control |
| Client workflow optimized around the vendor model | Custom pipelines accumulate around APIs, triggers, and identifiers that are expensive to replace |

Paid software also provides real value: support accountability, tested upgrades, long production history, training, and integrations. An open replacement must compete with that operational result, not merely remove a license check.

### 5.2 Problems in current open/free systems

| Problem | Consequence |
|---|---|
| Git LFS is a sidecar to Git | Pointer metadata and payload can be configured, transferred, retained, and repaired through different paths |
| Whole-file LFS identity/transfer | Small changes to huge files may store and transfer another whole object |
| Locking is not central to Git's branch model | Locks are easy to miss in clients and difficult to scope to future integration conflicts |
| Git repository graph is the usual security unit | Fine-grained read restrictions require repository splits or host-specific compromises |
| Sparse/partial Git has complex edge behavior | Nontechnical users see internal mechanics and unexpected network fetches |
| SVN has the right central primitives but an older experience | Studios must assemble asset preview, review, caches, modern branching, and engine workflows themselves |
| Open tools lack an artist-first product surface | “Use the CLI correctly” becomes a production risk and training tax |

### 5.3 The design thesis

The required model is **hybrid rather than ideologically centralized or distributed**:

- Large immutable payload and authoritative locks belong behind a service.
- Repository metadata and branches should be cheap enough for local inspection and temporary work.
- Mergeable files should support offline local checkpoints.
- Nonmergeable files cannot promise offline exclusivity; the client must say this plainly.
- Bulk data should move through content-addressed caches independently from consistent metadata transactions.
- The same native snapshot must include code and assets, even when a Git bridge exposes a code-oriented view.

---

## 6. Proposal: OpenGameVCS

### 6.1 Product promise

> A studio can version code and original assets in one atomic history, let each contributor materialize only the work they need, prevent conflicting binary edits across relevant branches, and run or leave the system without permission from a single vendor.

### 6.2 Principles

1. **One authoritative change, two optimized planes.** Metadata transactions and content transfer are separate internally but commit atomically.
2. **Cost proportional to change.** Status, sync, upload, and build materialization should scale with changed or selected data rather than total depot size wherever possible.
3. **Prevent before resolve.** Nonmergeable assets use visible, server-enforced coordination before edit.
4. **Artist workflow is a primary API.** The GUI and engine plugins are not wrappers added after the CLI.
5. **Open by construction.** Protocol, formats, server, clients, import/export, and conformance tests ship under an OSI-approved license.
6. **No hidden availability dependency.** Self-hosted deployments continue operating without a vendor account or license server.
7. **Boring durability.** Immutable checksummed objects, transactional metadata, routine verification, and rehearsed restore take priority over novel distributed machinery.
8. **Measured claims.** A published, reproducible game-repository benchmark replaces unqualified scale marketing.

### 6.3 Core data model

#### Immutable snapshot

A snapshot contains:

- one or more parent snapshot IDs;
- an immutable root tree ID;
- author and committer identities and timestamps;
- message, issue/review references, and policy result;
- the exact ordered set of path operations;
- optional signatures and provenance attestations.

A branch is an atomic pointer to a snapshot. Advancing it uses compare-and-swap so two writers cannot silently overwrite one another.

#### Stable file identity

Each tracked file has a stable `FileID` independent of its current path. Moves preserve the ID. This lets history, locks, and reviews follow an asset through rename rather than allowing a path rename to evade a lock. Tree entries hold path name, file ID, mode, content manifest ID, size, and content-policy class.

#### Content manifest and chunks

Large content is represented by a file manifest containing ordered chunk references and a whole-file digest. The first implementation should use:

- SHA-256 whole-file and object identifiers for broad interoperability;
- content-defined chunk boundaries for large files, with benchmarked size classes rather than one hard-coded size;
- compressed pack objects that group chunks for efficient sequential and range reads;
- a shared local cache across workspaces, using reflinks or hard links only when filesystem semantics are safe;
- resumable, parallel, idempotent upload/download;
- per-tenant or per-repository deduplication by default.

This approach has a working open precedent: the Xet protocol specifies content-defined chunks, content-addressed groups, reconstruction records, caching, and deduplicated upload ([Xet protocol](https://github.com/huggingface/hub-docs/blob/main/docs/xet/index.md), [Xet upload protocol](https://github.com/huggingface/hub-docs/blob/main/docs/xet/upload-protocol.md)). OpenGameVCS can reuse an audited implementation or the design, subject to license and workload benchmarks; it should not invent a new chunker casually.

Deduplication is an optimization, not a promise for every format. Already-compressed or encrypted assets may change broadly and deduplicate poorly. Metrics must report actual unique bytes saved.

#### Atomic submit

1. Client reads the branch head and creates a pending changelist.
2. It hashes/chunks modified files and uploads only objects the server reports missing.
3. The server verifies object presence and integrity.
4. In one metadata transaction it checks branch ancestry, ACLs, lock proofs, file policy, required review/CI, path collisions, and case/Unicode rules.
5. The server creates the snapshot, advances the branch pointer, records the audit event, and publishes an event.
6. Locks release, remain retained, or transfer according to their integration-domain policy.

No branch may point to a snapshot whose required content is absent. Failed or abandoned uploads remain unreferenced and are garbage-collected only after a safety window.

### 6.4 Workspace model

Every workspace has a versioned, reviewable specification:

- branch and baseline snapshot;
- include/exclude path rules;
- materialization policy: `full`, `metadata`, or `on-demand`;
- lock and merge policy overrides allowed by administrators;
- platform path rules;
- local cache location and limit.

The client keeps a compact local index and an OS change journal. It uses USN Journal, FSEvents, or inotify where reliable, with a safe reconciliation scan after missed events or unclean shutdown. `status` must not normally hash or scan every materialized file.

`checkpoint` records an immutable local manifest, message, and parent without advancing a server branch. Its new chunks remain in the shared local cache until publish. Users can chain, diff, squash, revert, and recover these checkpoints while offline. When connectivity returns, publishing performs the normal ancestry, permission, content, and lock checks; mergeable changes can rebase or merge if the branch advanced. A checkpoint that edits a hard-lockable file carries its original lock receipt, but the client must label exclusivity as unverified while offline and may require reconciliation before publish.

Initial releases should support explicit partial materialization. Transparent virtual filesystems should come later: placeholder behavior, antivirus interaction, editor access patterns, and Windows/macOS/Linux filesystem differences make virtualization a separate reliability program.

### 6.5 Locks and edit intent

OpenGameVCS needs a richer model than a boolean path lock.

| Mode | Purpose | Enforcement |
|---|---|---|
| Advisory intent | Warn that another user is editing mergeable or low-risk content | Visible in GUI/editor; does not reject submit |
| Hard lock | Prevent concurrent mutation of nonmergeable content | Server rejects conflicting submit; client makes the file read-only as a usability aid |
| Lock group | Reserve an asset plus required sidecars or a configured path set | One atomic lease and release operation |
| Folder/prefix lock | Controlled batch work such as localization drop or level conversion | Server evaluates descendants; use sparingly |

Hard locks have:

- stable FileID and current path;
- owner, workspace, base snapshot, and audit reason;
- scope: branch-local, integration-domain, or repository-global;
- configurable lease/heartbeat and a visible stale state;
- owner release, audited administrator takeover, and optional wait queue;
- notifications before expiry/takeover;
- final server-side validation in the submit transaction.

An **integration domain** groups branches whose binary changes are expected to merge to the same destination, similar in purpose to UVCS destination-branch Smart Locks. The server refuses a lock from an obsolete relevant revision and explains which branch/change is newer. A hard lock should not silently expire and become another user's lock while the original user is actively editing; expired leases enter a recoverable stale/takeover flow.

Filesystem read-only flags are not security boundaries. A user can bypass them; only server-side submit validation is authoritative.

### 6.6 Merge, branch, shelf, and review

- Cheap branches point to immutable snapshots; creating one copies metadata references, not payload.
- Text uses a normal three-way merge with pluggable drivers.
- Unity projects get a packaged `UnityYAMLMerge` driver and validation that asset serialization and `.meta` tracking are safe.
- Opaque binary policy defaults to lock or take-latest; the system never pretends to merge arbitrary binary formats.
- A shelf is an immutable, content-complete snapshot that does not advance a shared branch. It can run CI, receive comments, transfer ownership, and later submit.
- Reviews show text diff plus sandboxed preview adapters for images, audio waveforms, common 3D formats, and engine metadata. Original download still requires path permission.
- Review and snapshot metadata must avoid leaking names, messages, thumbnails, or dependency information from paths the viewer cannot read.

### 6.7 Storage and service architecture

```text
Desktop / CLI / Engine plugin / CI agent
                  |
          Metadata + lock API
                  |
        Stateless API / policy nodes
                  |
       Transactional metadata store
                  |
       event stream / audit / webhooks

Client <---- chunk API / signed transfer ----> object storage
   ^                                           ^
   |                                           |
shared local cache                    regional read-through cache
```

#### Starter deployment

- One signed server distribution or container bundle.
- One metadata database.
- Local filesystem or S3-compatible object storage.
- Built-in OIDC plus local bootstrap administrator.
- Built-in web administration, health checks, backup command, and restore verifier.

#### Production deployment

- Stateless API nodes behind a normal load balancer.
- Highly available transactional database using a well-supported open database such as PostgreSQL.
- Versioned/immutable S3-compatible object storage or a supported filesystem backend.
- Regional stateless content caches; no backup required for cache nodes.
- Optional event broker only when deployment scale requires it.

#### Global deployment

Metadata writes and locks retain one consistency authority per repository. Read metadata can use replicas when authorization and freshness permit. Payload uploads go directly to authorized object endpoints; regional caches serve immutable chunks. This keeps the common high-volume path local while avoiding multi-master lock ambiguity.

The project should not promise active/active branch-head writes in its first production release. Correct single-authority metadata with fast regional payload is a better initial tradeoff.

### 6.8 Security and tenancy

- OIDC/OAuth2, SAML through an identity proxy where appropriate, short-lived device login, service identities, and scoped personal tokens.
- Repository, branch, and path RBAC/ABAC with separate read, materialize, lock, submit, review, administer, and force-unlock permissions.
- Server-filtered trees and search. An unauthorized user must not infer hidden path names, sizes, hashes, thumbnails, messages, or object existence.
- Object access is authorized before a short-lived transfer grant. A content hash is never a bearer credential.
- Deduplication is scoped within a security tenant by default. Cross-tenant dedup can reveal content equality and complicate deletion/accounting.
- Encryption in transit and at rest; external KMS integration; keys are not derived solely from content hashes.
- Append-only audit events for permission changes, reads of sensitive paths if enabled, locks, forced unlocks, exports, retention changes, and administrative repair.
- Policy hooks run in a sandboxed, versioned environment with timeouts and deterministic inputs.
- Signed releases, SBOMs, reproducible-build work, dependency scanning, and a published security response process.

### 6.9 Durability, retention, and recovery

- Immutable chunks carry hashes and are verified on upload, read sampling, replication, and repair.
- Metadata backups and the corresponding object reachability boundary are recorded as one backup generation.
- Object-store versioning/immutability protects against accidental deletion; garbage collection is mark-and-sweep from snapshots, shelves, legal holds, and backup pins.
- Retention policy is explicit by path/content class, but deleting old revisions requires a privileged, auditable operation and a preview of affected snapshots.
- The server provides `verify`, `repair`, `backup`, and `restore --verify` commands with machine-readable output.
- Quarterly restore drills are part of the production runbook. A backup that has not been restored is not evidence of recoverability.

P4's documented separation of metadata, archive content, and logs—and the operational care needed to restore them—is a useful warning for this design ([P4 recovery model](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/backup.recovery.html)). OpenGameVCS should expose a simpler, generation-based contract.

### 6.10 Engine and tool integrations

#### Unreal Engine: first reference integration

- Implement the engine's source-control provider operations: connect, status, checkout/lock, add, delete, revert, sync, history, diff, check-in, and changelists.
- Show owner, branch scope, stale state, and lock queue in the Content Browser.
- Resolve One File Per Actor encoded files to meaningful actor/level names in pending changes.
- Refresh/hot-reload assets after in-editor sync where the engine supports it.
- Add an OpenGameVCS backend for Virtual Assets only after the core persistent-store contract is stable.
- Integrate Unreal Game Sync/Horde through immutable snapshot IDs and status APIs.

Epic exposes these operations through its Source Control module, providing a supported integration surface ([Unreal SourceControl API](https://dev.epicgames.com/documentation/unreal-engine/API/Developer/SourceControl)).

#### Unity: second reference integration

- Treat every asset and its `.meta` sidecar as a policy group for atomic operations.
- Detect unsafe serialization settings and offer a repository policy requiring text serialization for mergeable scenes/prefabs.
- Package `UnityYAMLMerge` configuration and surface unresolved semantic conflicts in the editor.
- Auto-acquire a hard lock before editing configured binary formats; display intent/owner/status in the Project window.
- Ignore and validate generated paths such as `Library`, temporary build products, and caches.

#### DCC and shell integration

The desktop agent supplies OS shell overlays, file picker/browse, lock-before-edit handlers, and a local HTTP/IPC SDK. Maya, Blender, Photoshop, audio, and custom tools can integrate without embedding storage or authentication logic.

Preview parsers run out of process with resource limits because creative file formats are an attack surface.

### 6.11 Build and CI workflow

- CI requests an immutable snapshot plus workspace specification, never “whatever is latest” after the job begins.
- Agents share a node-local chunk cache and materialize only required paths.
- Read-only snapshot mounts avoid server-side have-list records for every ephemeral worker.
- Machine credentials are short-lived and path-scoped.
- The VCS emits events only after the snapshot and all referenced content are durable.
- Build artifacts, package outputs, symbols, and engine-derived caches live in artifact/cache services with retention, provenance, and links back to the source snapshot. They are not placed in permanent source history by default.

### 6.12 Git and migration interoperability

#### Git bridge

- Import Git commits, branches, tags, author data, and LFS payload with checksum verification.
- Export an authorized path view as Git commits and LFS pointers.
- Maintain a mapping between native snapshot IDs and Git commit IDs.
- Begin with one-way mirrors. Bidirectional continuous synchronization is a later feature with explicit conflict rules; presenting it as trivial would be unsafe.
- Preserve existing Git code-review tooling during a staged adoption, while native snapshots remain authoritative for combined code/asset changes.

#### Perforce importer

Before importing, inventory depots, case mode, typemap/file types, streams and views, changelists, integrations, shelves, labels, permissions, triggers, jobs, and obliterated/retained revisions. The importer produces a dry-run fidelity report showing what maps exactly, approximately, or not at all. Every imported revision is checksum-verified and traceable to its original depot path/change number.

A safe migration uses a read-only historical import, incremental tailing or controlled dual-write window, user-acceptance comparison, CI shadow builds, and a reversible cutover. “Files arrived” is not sufficient proof that history and workflow survived.

#### Open export

The project publishes a versioned export format containing snapshots, trees, file IDs, manifests, chunks or external object references, branch/tag pointers, users, timestamps, signatures, audit events, policies, and lock history. A separate verifier reconstructs every file and validates every hash without running the OpenGameVCS server.

### 6.13 Administration and developer experience

- One guided install for a small studio; declarative configuration and infrastructure examples for production.
- Preflight project templates for Unreal, Unity, and Godot: ignore rules, merge drivers, lock policies, case rules, and recommended cache exclusions.
- Human task vocabulary in the GUI: **Get latest**, **Start editing**, **My changes**, **Share for review**, **Submit**, **Undo**, and **History**. The CLI can expose precise lower-level terms.
- Diagnostics answer “why is this file read-only?”, “who has it?”, “which branch has the newest revision?”, “why did submit fail?”, and “how many bytes will sync transfer?” without administrator access.
- Quota and cost views separate logical history bytes, unique stored bytes, cached bytes, replication, and egress.

---

## 7. What the proposal explicitly does not promise

1. **No magic binary merge.** Unstructured binary formats remain nonmergeable unless an engine/DCC-specific merge driver can prove otherwise.
2. **No offline exclusive-lock guarantee.** Offline work can be checkpointed, but exclusivity requires contact with the lock authority.
3. **No zero operations.** Self-hosters still own capacity, identity, monitoring, upgrades, backup, and incident response.
4. **No automatic savings for compressed assets.** Chunk reuse is measured per format and may be negligible.
5. **No P4 wire-compatible clone.** Migration and workflow compatibility are more valuable than permanently copying proprietary protocol behavior.
6. **No full DAM in the core.** Rich catalog, campaign, rights, and distribution workflows belong in integrations.
7. **No peer-to-peer or multi-master metadata in the MVP.** These add failure modes before core correctness is established.
8. **No replacement for project decomposition.** Engine features such as OFPA, good scene/prefab structure, and sensible repository boundaries still reduce contention.

---

## 8. Delivery plan

Building a trustworthy VCS is a multi-year systems product, not a weekend Git extension. A credible core team is roughly 8–12 full-time people across storage/distributed systems, cross-platform client/filesystems, desktop/UX, engine integrations, security/operations, and performance/QA, plus design-partner participation.

### Phase 0 — requirements, trace corpus, and format design (0–2 months)

Deliver:

- two or more design-partner studios, ideally one Unreal and one Unity team;
- anonymized workload traces and synthetic repositories;
- open data model and protocol draft;
- threat model, durability model, and migration-fidelity taxonomy;
- reproducible benchmark harness;
- architecture decision records for database, object format, chunker, and license.

Exit gate:

- the design can represent rename, branch, merge, lock, shelf, path ACL, and atomic submit without special cases that lose history;
- a clean-room reviewer can reconstruct the storage and authorization invariants from the spec.

### Phase 1 — native vertical slice / developer preview (3–8 months)

Deliver:

- server, CLI, metadata store, filesystem and S3-compatible content backends;
- immutable snapshots, branches, pending changelists, explicit partial workspaces;
- chunked resumable transfer and shared local cache;
- hard/advisory locks with stable file IDs and server enforcement;
- basic RBAC/path ACL, OIDC, audit, backup/restore/verify;
- Git/LFS importer and checksum report;
- headless CI snapshot materialization;
- Windows, macOS, and Linux correctness test matrix.

Exit gate:

- crash and network-fault tests cannot publish a snapshot with missing content;
- two clients cannot both submit a hard-locked file through any supported API;
- an unauthorized client cannot enumerate protected metadata or retrieve a known object hash;
- restore reconstructs every snapshot and passes independent hash verification.

### Phase 2 — studio alpha (9–14 months)

Deliver:

- artist desktop client;
- Unreal source-control plugin and changelist/OFPA usability;
- shelves, web review, image/audio preview, policy hooks;
- regional cache, transfer accounting, repair and observability dashboards;
- Perforce importer with fidelity report;
- one-way Git mirror and snapshot-to-commit mapping;
- signed installers and upgrade/rollback process.

Exit gate:

- a design-partner team shadows real production for at least eight weeks;
- artists complete common tasks without a CLI and with measured error/support rates;
- CI produces byte-identical builds or explained deterministic differences from the incumbent snapshot;
- a region-cache loss causes performance degradation but no data loss.

### Phase 3 — production beta (15–24 months)

Deliver:

- Unity integration and packaged semantic merge;
- HA metadata deployment, rolling upgrades, cross-region DR;
- branch integration domains and retained-lock workflow;
- scalable review/search/indexing with path-safe authorization;
- full open export and independent verifier;
- conformance suite and third-party SDK;
- optional workspace virtualization preview after explicit materialization is stable.

Exit gate:

- at least two studios run a production project with documented support and rollback plans;
- published benchmark and 90-day reliability results meet the targets below;
- a complete export is imported into a clean instance run by another organization.

### Phase 4 — ecosystem and long-term scale (after 24 months)

- virtual filesystem general availability;
- additional DCC/engine plugins;
- independent managed-hosting providers;
- advanced replication and cache placement;
- semantic asset-diff SDK;
- neutral-foundation governance and long-term compatibility policy.

---

## 9. Acceptance criteria and benchmark

Targets are hypotheses to validate, not current product claims. Results must publish hardware, topology, dataset composition, cache state, compression, and command definition.

### 9.1 Reference datasets

1. **Code-heavy:** 250,000 paths, deep text history, many branches.
2. **Unreal production:** at least 1,000,000 paths, multi-terabyte binary history, OFPA, large textures/audio, frequent small changelists.
3. **Unity production:** text scenes/prefabs, `.meta` sidecars, large imported source assets, semantic merges.
4. **Large mutable binaries:** several 10–100 GiB files with insertions, replacements, compressed variants, and random rewrites.
5. **Global simulation:** 20–200 ms RTT, constrained links, packet loss, cold/warm regional caches.

### 9.2 Initial performance SLO candidates

| Operation | Candidate target |
|---|---|
| Warm `status` at 1M tracked paths, no changes | p95 under 2 seconds without a full-tree hash scan |
| Status with 1,000 changed paths | p95 under 5 seconds after journal reconciliation |
| Create metadata-only partial workspace over 1M paths | under 60 seconds on reference workstation |
| Incremental sync | metadata overhead under 5 seconds plus missing payload transfer time |
| Large-file edit transfer | no more than 1.2× unique changed chunk bytes where the format permits stable chunking; publish exceptions by format |
| Same-region lock acquire | p95 under 250 ms |
| 200 ms RTT lock acquire | p95 under 1 second, excluding interactive auth |
| Atomic submit with 100k path operations, payload pre-uploaded | under 30 seconds on reference production deployment |
| Regional cache hit | zero origin payload bytes; content hash identical |
| Single-node recovery | documented RPO/RTO and complete independent verification; initial target RPO ≤5 min, RTO ≤60 min for metadata |

### 9.3 Correctness and abuse tests

- power loss at every submit phase;
- branch-head race and lock-acquire race;
- interrupted multipart upload, retry, and duplicate request;
- bit flip in local cache, edge cache, object store, manifest, and metadata backup;
- force unlock during active edit;
- rename/move while locked and case-only rename on each operating system;
- Unicode normalization collision, reserved Windows names, long paths, symlinks, executable bits, and files over 4 GiB;
- path ACL changes during sync/review/export;
- guessed object hashes and presigned-URL replay;
- malicious preview file and policy hook;
- database rollback with newer object payload and object rollback with newer metadata;
- old client against new server and new client against old supported server.

### 9.4 Problem-to-proof traceability

| Existing pain | Proposed mechanism | Proof required before claiming it solved |
|---|---|---|
| Proprietary license/vendor lock | Apache-2.0 implementation, open spec, full export | Independent party deploys, exports, verifies, and reimports without vendor service |
| Re-uploading giant changed binaries | Content-defined chunks and missing-chunk negotiation | Measure transferred/stored unique bytes across representative formats |
| Huge local workspace | Partial materialization, shared cache, later virtualization | Cold/warm disk and network results for artist roles on production-sized tree |
| Conflicting binary work | Auto-lock, integration-domain locks, atomic validation | Concurrent clients and cross-branch collision tests cannot both submit |
| Git/LFS split-brain | Content-complete transactional snapshot | Fault injection never publishes missing payload; verifier detects corruption |
| Nontechnical workflow failures | Artist GUI and engine integration | Task-based usability study and support/error telemetry with real artists |
| WAN bottleneck | Immutable regional cache and direct object transfer | Origin/cached byte counts and p95 task time under controlled RTT/loss |
| Complex recovery | Backup generations and independent verifier | Timed bare-environment restore drills with all hashes and refs validated |
| Weak path confidentiality | Server-filtered trees plus authorized object grants | Red-team enumeration and known-hash tests reveal no protected metadata/content |
| Build workspace overhead | Read-only snapshot materialization and node cache | Parallel clean-agent benchmark without per-agent server state explosion |

---

## 10. Procurement bakeoff for an existing studio

A four-to-six-week bakeoff should compare the incumbent and shortlisted products with the same depot slice, users, hardware class, region links, and tasks.

### 10.1 Prepare representative input

- 10–20% of a real project by active working-set behavior, not merely directory size;
- complete history for representative large mutable assets;
- actual Unreal/Unity sidecar and scene patterns;
- actual CI sync/build workflow;
- real roles and access boundaries;
- one remote or simulated high-latency site.

### 10.2 Measure tasks, not slogans

1. New artist setup to first useful asset.
2. New programmer setup to first build.
3. Morning incremental sync, cold and warm cache.
4. Open/lock/edit/submit of a binary asset.
5. Two users attempt the same asset on different branches.
6. Text branch, review, merge, and rollback.
7. Change spanning code, engine package, and sidecar.
8. CI materialization across 20 concurrent agents.
9. User removal and contractor path restriction.
10. Backup, destructive test, restore, and checksum validation.
11. Full export of the pilot and reconstruction outside the service.

Record wall time, bytes transferred, disk footprint, CPU/memory, p50/p95 latency, failed/retried operations, administrator hours, user errors, support intervention, and unrecoverable semantic loss.

### 10.3 Compare total cost of ownership

Use a three-year model:

```text
TCO = licenses and support
    + primary, replica, cache, and backup storage
    + compute and database
    + network egress and inter-region transfer
    + VCS/platform engineering time
    + upgrade, recovery, and compliance labor
    + migration and training
    + expected cost of outage or lost work
```

Count human and service identities according to each vendor's actual terms. Model peak contractors and build agents, not only current employees. Run sensitivity analysis for repository growth, cache hit rate, region count, and egress.

---

## 11. Governance and licensing

### Recommended structure

- **Apache License 2.0** for server, clients, plugins, SDKs, conformance tools, and formats: permissive adoption plus an explicit patent grant.
- Public roadmap, design proposals, security process, compatibility policy, and release engineering.
- Developer Certificate of Origin rather than an asymmetric contributor agreement that allows one company to close community work.
- Technical steering committee with elected maintainers and recorded decisions.
- Two anchor studios from different engine ecosystems before 1.0; move trademarks and critical infrastructure to a neutral foundation when governance is viable.
- No “open core” split that places durability, export, locks, path security, HA correctness, or engine integrations behind a proprietary tier. Commercial providers can sell hosting, support, migration, compliance packaging, and operations.
- File and protocol versions have documented compatibility windows and test vectors. A long-term-support release receives security and data-format fixes for a declared period.

### Sustainable commercial ecosystem

Open source succeeds when somebody is paid to maintain the unglamorous parts. A healthy ecosystem can include:

- managed regional hosting;
- 24×7 support and incident response;
- migration and repository-health services;
- certified storage/database distributions;
- enterprise identity/compliance bundles;
- custom engine/DCC integrations;
- training and production consulting.

Studios retain the ability to switch providers or operate the same upstream software themselves.

---

## 12. Principal risks and mitigations

| Risk | Why it matters | Mitigation |
|---|---|---|
| Scope is too broad | Storage, VCS semantics, GUI, engines, security, and HA can overwhelm a new project | Vertical slices, strict non-goals, one engine first, production gates before features |
| Data loss or silent corruption | A VCS is a system of record | Immutable hashes, transactional reference updates, fault injection, independent verifier, restore drills |
| Chunking disappoints | Compressed/encrypted assets may rewrite globally | Per-format benchmarks, transparent metrics, whole-object fast path, never promise a universal ratio |
| Lock model blocks work | Overly broad/stale locks serialize a studio | Advisory intent, lock groups, integration domains, queues, visible ownership, audited takeover, contention metrics |
| Lock model fails across branches | Two legal edits may collide only at integration | Stable file IDs, relevant-lineage check, destination/integration-domain scope, retained state |
| Filesystem edge cases corrupt work | Game teams are cross-platform and use unusual names/large files | Explicit repository case/Unicode policy and exhaustive OS/filesystem matrix |
| Path ACL leaks through metadata/CAS | Game IP and external partners require real isolation | Authorization-aware trees/search/reviews, tenant-scoped dedup, object grants, red-team tests |
| Artist UI arrives too late | A technically good backend still fails adoption | Artist task journey and engine plugin in the first studio alpha, dedicated UX ownership |
| Git bridge becomes the product | Compatibility constraints can preserve Git's core limitations | Native model remains authoritative; bridge has explicit fidelity boundaries |
| Migration loses semantics | History without streams, types, integrations, labels, or permissions may be unusable | Inventory, fidelity report, checksums, shadow CI, reversible cutover, original-ID mapping |
| Project is captured by one vendor | Open code alone does not ensure open direction | Neutral governance, DCO, public compatibility tests, multiple providers and design partners |
| Operations remain too hard | Open source without reliable operations will not displace P4 | Starter bundle, supported reference architectures, observability, upgrade/restore automation |

---

## 13. Recommended decision

### For a studio selecting a VCS now

1. Classify the project as code-heavy or asset-heavy, record peak team/contractor count, repository growth, required regions, and path-security boundaries.
2. Use Git + LFS as the low-complexity baseline for small/code-heavy teams, with CI enforcement for LFS pointers and lock policy.
3. Use P4 as the maturity baseline for large Unreal/AAA workflows; do not assess license cost without administrator/infrastructure cost.
4. Add UVCS for artist-heavy/Unity workflows and Diversion for a modern managed contender.
5. If fully open source is mandatory, test SVN against Git + LFS honestly; neither is the complete end state described here.
6. Require every finalist to complete the backup/restore and export tasks, not only sync/submit demos.

### For an organization funding an open alternative

Proceed only as a **shared infrastructure program with design-partner studios**, not as a speculative feature clone. Fund Phase 0 and the Phase 1 vertical slice first. Continue only if the implementation proves atomic content-complete commits, authoritative cross-branch locks, partial workspace performance, path confidentiality, and verified restore.

The strongest strategic architecture is a new native metadata/locking core with open chunk storage and a Git/LFS bridge. Extending Git LFS is a useful transitional product but cannot cleanly supply stable file identity, integrated branch-aware locks, path-confidential repository views, and a simple artist workspace without accumulating host-specific layers. Extending SVN starts closer to the required central authority but still requires rebuilding large-asset transfer, modern branches/review, caches, local work, and the product experience. A clean native core costs more initially but directly addresses the actual gap.

---

## Appendix A — Source register

Primary sources used for product capabilities and design precedents:

- **Epic Games:** [Scaling an Unreal team](https://dev.epicgames.com/documentation/en-us/unreal-engine/resources-for-scaling-your-unreal-engine-team), [Source Control](https://dev.epicgames.com/documentation/en-us/unreal-engine/source-control-in-unreal-engine), [Virtual Assets](https://dev.epicgames.com/documentation/unreal-engine/overview-of-virtual-assets-in-unreal-engine), [One File Per Actor](https://dev.epicgames.com/documentation/unreal-engine/one-file-per-actor-in-unreal-engine), [SourceControl API](https://dev.epicgames.com/documentation/unreal-engine/API/Developer/SourceControl).
- **Perforce:** [P4 pricing](https://www.perforce.com/resources/vcs/helix-core-pricing), [basic architecture](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/intro.architecture.html), [exclusive checkout](https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/P4Guide/resolve.lock.exclusive.html), [streams](https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/P4Guide/streams.configure.html), [proxy](https://help.perforce.com/helix-core/server-apps/p4sag/2024.2/Content/P4SAG/chapter.proxy.html), [deployment architecture](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/deployment-architecture.html), [disaster recovery](https://help.perforce.com/helix-core/server-apps/p4sag/current/Content/P4SAG/secure-prepare-disaster-recover.html).
- **Git / Git LFS:** [Git data model](https://git-scm.com/docs/gitdatamodel.html), [partial clone](https://git-scm.com/docs/git-clone.html), [sparse checkout](https://git-scm.com/docs/git-sparse-checkout.html), [Scalar](https://git-scm.com/docs/scalar/2.53.0.html), [Git LFS](https://git-lfs.com/), [LFS specification](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md), [locking API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md), [configuration](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc), [FAQ](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-faq.adoc).
- **Unity:** [UVCS overview](https://docs.unity.com/ugs/en-us/manual/devops/manual/unity-devops-home), [Gluon](https://docs.unity.com/unity-version-control/gluon/gluon), [Smart Locks](https://docs.unity.com/en-us/unity-version-control/smart-locks), [free plan](https://docs.unity.com/en-us/devops/pricing/free-plan), [Smart Merge](https://docs.unity3d.com/6000.0/Documentation/Manual/SmartMerge.html), [asset serialization](https://docs.unity3d.com/6000.0/Documentation/Manual/class-EditorManager.html).
- **Apache Subversion:** [project](https://subversion.apache.org/), [license](https://subversion.apache.org/docs/community-guide/general), [locks](https://svnbook.red-bean.com/en/1.8/svn.ref.svn.c.lock.html), [path authorization](https://svnbook.red-bean.com/en/1.8/svn.serverconfig.pathbasedauthz.html), [cheap branches](https://svnbook.red-bean.com/en/1.8/svn.branchmerge.using.html).
- **Mercurial:** [commands](https://mercurial-scm.org/help/commands), [clone](https://mercurial-scm.org/help/commands/clone), [largefiles repository requirement](https://mercurial-scm.org/missing-requirement), [official-project locking discussion](https://lists.mercurial-scm.org/pipermail/mercurial/2023-November/106364.html).
- **Diversion:** [game-development product](https://www.diversion.dev/game-development), [hard locks](https://docs.diversion.dev/hard-locks).
- **Open building blocks:** [Forgejo LFS configuration](https://forgejo.org/docs/latest/admin/config-cheat-sheet/), [Forgejo object storage](https://forgejo.org/docs/v15.0/admin/setup/storage/), [Xet protocol](https://github.com/huggingface/hub-docs/blob/main/docs/xet/index.md), [Xet upload protocol](https://github.com/huggingface/hub-docs/blob/main/docs/xet/upload-protocol.md).

## Appendix B — Questions for design-partner interviews

1. Which files cause the most lost work, and how often does it happen?
2. Which roles need which paths, and how often do those working sets change?
3. What are cold setup, daily sync, build sync, submit, and restore times today?
4. How many active, stale, forcibly released, and cross-branch locks exist per week?
5. Which assets are mergeable in theory but not safely mergeable in practice?
6. Which metadata/sidecar files must move atomically with an asset?
7. Which P4 triggers, Git hooks, review gates, or custom tools are production-critical?
8. What permissions must hide existence and metadata, not merely prevent writes?
9. What regions, RTTs, link capacities, and egress constraints matter?
10. How many ephemeral CI workspaces are created per day and how much content do they duplicate?
11. Which history, labels, shelves, integrations, and audit records must survive migration?
12. What RPO/RTO has actually been exercised in a restore drill?
13. What would make artists refuse the new tool after one week?
14. What exact export would make the studio comfortable adopting a new VCS?
