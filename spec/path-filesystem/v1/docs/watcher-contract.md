# Watcher cursor and reconciliation contract

Watcher acceleration never establishes truth by itself. Persisted state is a
closed `ogvcs.path/watcher-state/v1` document with adapter kind, opaque bounded
cursor, generation, optional live session, authoritative-clean bit,
reconciliation-required bit, and a registered reason.

An initial workspace requires reconciliation. Starting a watcher session makes
clean status false until the contiguous batch has been applied to the index.
The batch's `fromCursor` must equal the durable cursor; its `toCursor` becomes
durable with the index decision, but a failed index update immediately marks
reconciliation required. Overflow, cursor mismatch, adapter error,
unsupported resume, corrupt state, or a process restart with a live session
sets reconciliation-required and cannot be acknowledged away.

Only a bounded full reconciliation may increment the generation, install a new
adapter cursor, clear the session/reason, and set authoritative clean. Normal
shutdown is accepted only from a clean, non-reconciling live session. A stop
remains clean only when the adapter explicitly proves resumable continuity;
otherwise it clears the session and records `unsupported-resume` with
reconciliation required. State writes use the same staged atomic-write rules as
workspace control records.

The portable Node `fs.watch` adapter filters the private control namespace,
bounds queue/event processing, and races source and index callback promises. It
establishes the native subscription before invoking the caller's bounded full
reconciliation callback. Only that post-subscription reconciliation may install
the new synthetic generation/cursor and start the session; events that occur
during reconciliation remain queued behind that cursor. Opening without the
callback is rejected. The adapter always records `unsupported-resume` on close,
so a stopped interval is covered by the next post-subscription reconciliation
and a synthetic cursor cannot be reused. Ambiguous/null filenames, queue
overflow, iterator termination, and callback failure force reconciliation.
Because the portable Node iterator exposes no authenticated queue-drained
barrier, an ordinary delivered notification advances its synthetic cursor but
never promotes the live index to authoritative clean. More native events may
already be queued. Consumers use those batches as acceleration and obtain
authoritative-clean status only from a new bounded reconciliation; stronger
native journal adapters may mark a complete contiguous batch clean when their
cursor API proves the barrier.
Native USN, FSEvents, or inotify adapters may persist resumable cursors only
when their host API proves continuity, and must translate gaps/overflow to the
same contract.
