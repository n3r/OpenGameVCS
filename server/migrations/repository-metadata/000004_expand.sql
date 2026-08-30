BEGIN;

-- Deterministic bounded breadth-first traversal stays inside PostgreSQL so a
-- deep linear history does not require one network round trip per parent.
-- Duplicate DAG paths count against the work budget and are de-duplicated by
-- the caller; hostile merge amplification therefore terminates explicitly.
CREATE FUNCTION ogvcs_metadata.bounded_snapshot_ancestry(
    requested_repository_id uuid,
    requested_snapshot_digest bytea,
    requested_maximum_depth integer,
    requested_maximum_work integer
)
RETURNS TABLE (
    snapshot_digest bytea,
    traversal_depth integer,
    visit_ordinal integer,
    has_parents boolean
)
LANGUAGE plpgsql
STABLE
AS $ogvcs$
DECLARE
    pending_digests bytea[] := ARRAY[requested_snapshot_digest];
    pending_depths integer[] := ARRAY[0];
    next_index integer := 1;
    emitted integer := 0;
    current_digest bytea;
    current_depth integer;
    parent_row record;
BEGIN
    IF octet_length(requested_snapshot_digest) <> 32
       OR requested_maximum_depth < 0
       OR requested_maximum_depth > 100000
       OR requested_maximum_work < 1
       OR requested_maximum_work > 100001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid bounded snapshot ancestry request';
    END IF;

    WHILE next_index <= COALESCE(array_length(pending_digests, 1), 0)
          AND emitted < requested_maximum_work LOOP
        current_digest := pending_digests[next_index];
        current_depth := pending_depths[next_index];
        emitted := emitted + 1;

        snapshot_digest := current_digest;
        traversal_depth := current_depth;
        visit_ordinal := emitted;
        SELECT EXISTS (
            SELECT 1
            FROM ogvcs_metadata.snapshot_parents AS parent
            WHERE parent.repository_id = requested_repository_id
              AND parent.snapshot_digest = current_digest
        ) INTO has_parents;
        RETURN NEXT;

        IF current_depth < requested_maximum_depth THEN
            FOR parent_row IN
                SELECT parent.parent_snapshot_digest
                FROM ogvcs_metadata.snapshot_parents AS parent
                WHERE parent.repository_id = requested_repository_id
                  AND parent.snapshot_digest = current_digest
                ORDER BY parent.ordinal
            LOOP
                IF COALESCE(array_length(pending_digests, 1), 0)
                   < requested_maximum_work THEN
                    pending_digests := array_append(
                        pending_digests,
                        parent_row.parent_snapshot_digest
                    );
                    pending_depths := array_append(pending_depths, current_depth + 1);
                END IF;
            END LOOP;
        END IF;
        next_index := next_index + 1;
    END LOOP;
END
$ogvcs$;

COMMIT;
