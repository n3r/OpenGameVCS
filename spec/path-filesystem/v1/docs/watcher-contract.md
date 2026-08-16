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
shutdown is accepted only from a clean, non-reconciling live session. State
writes use the same staged atomic-write rules as workspace control records.

The portable Node `fs.watch` adapter filters the private control namespace,
bounds queue/event processing, races source and index callback promises, and
never claims cursor resume after process restart. Ambiguous/null filenames,
queue overflow, iterator termination, and callback failure force
reconciliation. Native USN, FSEvents, or inotify adapters may persist resumable
cursors only when their host API proves continuity, and must translate
gaps/overflow to the same contract.
