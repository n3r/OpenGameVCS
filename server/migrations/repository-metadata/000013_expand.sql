BEGIN;

-- Freeze this additive bridge correction against the exact v12 proof-store
-- authority. The migration runner checks the whole predecessor chain; this
-- local fence also prevents an alternate host from applying v13 out of order.
DO $ogvcs$
BEGIN
    IF (
        SELECT count(*)
        FROM ogvcs_metadata.schema_migrations
        WHERE version = 12
          AND state = 'completed'
          AND (
              (phase = 'expand' AND checksum_sha256 =
                  'b3a9e54ca1cc526451e38072c0732c946e26a7bbb07bb45f7514e25949d70dac')
              OR (phase = 'migrate' AND checksum_sha256 =
                  '5917465778e8d6b882d4b3a6d6c95b0ddd66c62bab34e31b90463cbb418a7a27')
              OR (phase = 'contract' AND checksum_sha256 =
                  'dfa4ffa12248931aeeaf76b4fe2f9040862fe7764c6fde20042536511d138d74')
          )
    ) <> 3 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'repository metadata v13 predecessor authority mismatch';
    END IF;
END;
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.aggregate_identity_mapping_field_v13(value bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT int8send(octet_length(value)::bigint) || value
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.lifecycle_object_id_v13(
    object_kind smallint,
    object_digest bytea
)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT 'ogvcs:v1:' || CASE object_kind
        WHEN 1 THEN 'chunk'
        WHEN 2 THEN 'content-manifest'
        WHEN 3 THEN 'tree'
        WHEN 4 THEN 'change-set'
        WHEN 5 THEN 'asset-group-set'
        WHEN 6 THEN 'repository-descriptor'
        WHEN 7 THEN 'snapshot'
        WHEN 8 THEN 'shelf-revision'
        WHEN 9 THEN 'provenance'
        WHEN 10 THEN 'attestation'
        WHEN 11 THEN 'conflict-set'
        ELSE NULL
    END || ':sha256:' || encode(object_digest, 'hex')
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.aggregate_identity_mapping_item_digest_v13(
    lifecycle_plan_id uuid,
    lifecycle_global_ordinal integer,
    identity_plan_id text,
    identity_item_ordinal integer,
    object_kind smallint,
    object_digest bytea,
    resource_digest bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT sha256(
        convert_to('OGVCS-LIFECYCLE-AGGREGATE-IDENTITY-MAPPING-ITEM-V1', 'UTF8')
        || decode('00', 'hex')
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            uuid_send(lifecycle_plan_id)
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            int4send(lifecycle_global_ordinal)
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            convert_to(identity_plan_id, 'UTF8')
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            int4send(identity_item_ordinal)
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(int2send(object_kind))
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(object_digest)
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(resource_digest)
    )
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.aggregate_identity_mapping_digest_v13(
    lifecycle_plan_id uuid,
    identity_plan_id text,
    object_count integer,
    lifecycle_plan_digest bytea,
    identity_decision_digest bytea,
    identity_resource_projection_digest bytea,
    ordered_item_digests bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT sha256(
        convert_to('OGVCS-LIFECYCLE-AGGREGATE-IDENTITY-MAPPING-SEAL-V1', 'UTF8')
        || decode('00', 'hex')
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            uuid_send(lifecycle_plan_id)
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            convert_to(identity_plan_id, 'UTF8')
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(int4send(object_count))
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(lifecycle_plan_digest)
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(identity_decision_digest)
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(
            identity_resource_projection_digest
        )
        || ogvcs_metadata.aggregate_identity_mapping_field_v13(ordered_item_digests)
    )
$ogvcs$;

-- The lifecycle plan remains ordered by its opaque storage keys. This seal is
-- the immutable, typed one-to-one relation to the independently canonical
-- OGVCS-009 identity plan; it does not derive either plan or expose a route.
CREATE TABLE ogvcs_metadata.lifecycle_aggregate_identity_seals (
    lifecycle_plan_id uuid PRIMARY KEY
        REFERENCES ogvcs_metadata.lifecycle_publication_plan_seals(plan_id),
    identity_plan_id text NOT NULL UNIQUE
        REFERENCES ogvcs_identity.aggregate_decision_commitments(plan_id),
    object_count integer NOT NULL CHECK (object_count BETWEEN 1 AND 100000),
    lifecycle_plan_digest bytea NOT NULL CHECK (octet_length(lifecycle_plan_digest) = 32),
    identity_decision_digest bytea NOT NULL
        CHECK (octet_length(identity_decision_digest) = 32),
    identity_resource_projection_digest bytea NOT NULL
        CHECK (octet_length(identity_resource_projection_digest) = 32),
    mapping_digest bytea NOT NULL UNIQUE CHECK (octet_length(mapping_digest) = 32),
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (lifecycle_plan_id, identity_plan_id)
);

CREATE TABLE ogvcs_metadata.lifecycle_aggregate_identity_items (
    lifecycle_plan_id uuid NOT NULL,
    lifecycle_global_ordinal integer NOT NULL
        CHECK (lifecycle_global_ordinal BETWEEN 0 AND 99999),
    identity_plan_id text NOT NULL,
    identity_item_ordinal integer NOT NULL
        CHECK (identity_item_ordinal BETWEEN 0 AND 99999),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 11),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    resource_digest bytea NOT NULL CHECK (octet_length(resource_digest) = 32),
    mapping_item_digest bytea NOT NULL CHECK (octet_length(mapping_item_digest) = 32),
    PRIMARY KEY (lifecycle_plan_id, lifecycle_global_ordinal),
    UNIQUE (lifecycle_plan_id, identity_item_ordinal),
    UNIQUE (lifecycle_plan_id, mapping_item_digest),
    FOREIGN KEY (lifecycle_plan_id, lifecycle_global_ordinal)
        REFERENCES ogvcs_metadata.lifecycle_publication_plan_items(
            plan_id, global_ordinal
        ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (identity_plan_id, identity_item_ordinal)
        REFERENCES ogvcs_identity.aggregate_plan_resources(plan_id, item_ordinal)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (lifecycle_plan_id, identity_plan_id)
        REFERENCES ogvcs_metadata.lifecycle_aggregate_identity_seals(
            lifecycle_plan_id, identity_plan_id
        ) DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION ogvcs_metadata.reject_sealed_aggregate_identity_item_insert_v13()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_aggregate_identity_seals AS seal
        WHERE seal.lifecycle_plan_id = NEW.lifecycle_plan_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'aggregate identity mapping is sealed';
    END IF;
    RETURN NEW;
END;
$ogvcs$;

CREATE TRIGGER lifecycle_aggregate_identity_items_sealed_v13
BEFORE INSERT ON ogvcs_metadata.lifecycle_aggregate_identity_items
FOR EACH ROW EXECUTE FUNCTION
    ogvcs_metadata.reject_sealed_aggregate_identity_item_insert_v13();

CREATE FUNCTION ogvcs_metadata.validate_aggregate_identity_seal_v13()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_publication_plans AS lifecycle_plan
        JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS lifecycle_seal
          ON lifecycle_seal.plan_id = lifecycle_plan.plan_id
        JOIN ogvcs_identity.aggregate_decision_commitments AS decision
          ON decision.plan_id = NEW.identity_plan_id
        JOIN ogvcs_identity.aggregate_plans AS identity_plan
          ON identity_plan.plan_id = decision.plan_id
        WHERE lifecycle_plan.plan_id = NEW.lifecycle_plan_id
          AND lifecycle_seal.object_count = NEW.object_count
          AND lifecycle_plan.declared_object_count = NEW.object_count
          AND lifecycle_seal.plan_digest = NEW.lifecycle_plan_digest
          AND lifecycle_plan.declared_plan_digest = NEW.lifecycle_plan_digest
          AND identity_plan.state IN ('authorized', 'consumed')
          AND identity_plan.item_count = NEW.object_count
          AND decision.resource_count = NEW.object_count
          AND decision.decision_digest = NEW.identity_decision_digest
          AND identity_plan.decision_digest = NEW.identity_decision_digest
          AND decision.resource_digest_projection_digest =
              NEW.identity_resource_projection_digest
          AND identity_plan.resource_digest_projection_digest =
              NEW.identity_resource_projection_digest
          AND decision.metadata_tenant_id = lifecycle_plan.tenant_id::text
          AND decision.metadata_repository_id = lifecycle_plan.repository_id::text
          AND decision.tenant_id =
              'tenant.' || replace(lifecycle_plan.tenant_id::text, '-', '')
          AND decision.repository_id =
              'repository.' || replace(lifecycle_plan.repository_id::text, '-', '')
          AND decision.subject_digest = lifecycle_plan.subject_digest
          AND decision.authenticated_scope_digest =
              lifecycle_plan.idempotency_scope_digest
          AND decision.authority_epoch = lifecycle_plan.authorization_epoch
          AND decision.permission = 'submit'
          AND decision.capability = 'submit.consume-publication'
          AND decision.reference_name = lifecycle_plan.authorization_reference
          AND decision.snapshot_id = lifecycle_plan.authorization_snapshot
          AND (
              SELECT count(*)
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
          ) = NEW.object_count
          AND (
              SELECT min(mapping.lifecycle_global_ordinal)
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
          ) = 0
          AND (
              SELECT max(mapping.lifecycle_global_ordinal)
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
          ) = NEW.object_count - 1
          AND (
              SELECT min(mapping.identity_item_ordinal)
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
          ) = 0
          AND (
              SELECT max(mapping.identity_item_ordinal)
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
          ) = NEW.object_count - 1
          AND NOT EXISTS (
              SELECT 1
              FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
              JOIN ogvcs_metadata.lifecycle_publication_plan_items AS lifecycle_item
                ON lifecycle_item.plan_id = mapping.lifecycle_plan_id
               AND lifecycle_item.global_ordinal = mapping.lifecycle_global_ordinal
              JOIN ogvcs_identity.aggregate_plan_resources AS identity_resource
                ON identity_resource.plan_id = mapping.identity_plan_id
               AND identity_resource.item_ordinal = mapping.identity_item_ordinal
              WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                AND mapping.identity_plan_id = NEW.identity_plan_id
                AND (
                    mapping.object_kind <> lifecycle_item.object_kind
                    OR mapping.object_digest <> lifecycle_item.object_digest
                    OR mapping.resource_digest <> lifecycle_item.resource_opaque_digest
                    OR mapping.resource_digest <> identity_resource.resource_digest
                    OR identity_resource.resource_type <> 'object'
                    OR identity_resource.path_key IS NOT NULL
                    OR identity_resource.file_id IS NOT NULL
                    OR identity_resource.resource_name IS NOT NULL
                    OR identity_resource.object_id IS DISTINCT FROM
                        ogvcs_metadata.lifecycle_object_id_v13(
                            lifecycle_item.object_kind,
                            lifecycle_item.object_digest
                        )
                    OR mapping.mapping_item_digest <>
                        ogvcs_metadata.aggregate_identity_mapping_item_digest_v13(
                            mapping.lifecycle_plan_id,
                            mapping.lifecycle_global_ordinal,
                            mapping.identity_plan_id,
                            mapping.identity_item_ordinal,
                            mapping.object_kind,
                            mapping.object_digest,
                            mapping.resource_digest
                        )
                )
          )
          AND NEW.mapping_digest =
              ogvcs_metadata.aggregate_identity_mapping_digest_v13(
                  NEW.lifecycle_plan_id,
                  NEW.identity_plan_id,
                  NEW.object_count,
                  NEW.lifecycle_plan_digest,
                  NEW.identity_decision_digest,
                  NEW.identity_resource_projection_digest,
                  decode(COALESCE((
                      SELECT string_agg(
                          encode(mapping.mapping_item_digest, 'hex'),
                          '' ORDER BY mapping.identity_item_ordinal
                      )
                      FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS mapping
                      WHERE mapping.lifecycle_plan_id = NEW.lifecycle_plan_id
                        AND mapping.identity_plan_id = NEW.identity_plan_id
                  ), ''), 'hex')
              )
    ) INTO complete;

    IF NOT COALESCE(complete, false) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'aggregate identity mapping is incomplete';
    END IF;
    RETURN NULL;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER lifecycle_aggregate_identity_seal_complete_v13
AFTER INSERT ON ogvcs_metadata.lifecycle_aggregate_identity_seals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
    ogvcs_metadata.validate_aggregate_identity_seal_v13();

-- New aggregate applications must consume the exact identity plan sealed to
-- their lifecycle plan. Existing committed v10 evidence is not rewritten and
-- remains readable because this trigger applies only to new insertions.
CREATE FUNCTION ogvcs_metadata.validate_aggregate_identity_application_v13()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    IF NEW.application_kind <> 'aggregate' THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS evidence
        JOIN ogvcs_metadata.lifecycle_aggregate_identity_seals AS mapping
          ON mapping.lifecycle_plan_id = evidence.lifecycle_plan_id
         AND mapping.identity_plan_id = evidence.identity_plan_id
        WHERE evidence.application_id = NEW.application_id
          AND evidence.lifecycle_plan_id = NEW.plan_id
          AND mapping.object_count = NEW.object_count
          AND mapping.lifecycle_plan_digest = NEW.lifecycle_plan_digest
          AND mapping.identity_decision_digest = evidence.identity_decision_digest
          AND mapping.identity_resource_projection_digest =
              evidence.resource_digest_projection_digest
    ) INTO complete;

    IF NOT COALESCE(complete, false) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'aggregate application lacks exact identity mapping';
    END IF;
    RETURN NEW;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER lifecycle_aggregate_identity_application_complete_v13
AFTER INSERT ON ogvcs_metadata.lifecycle_applications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
    ogvcs_metadata.validate_aggregate_identity_application_v13();

CREATE TRIGGER lifecycle_aggregate_identity_seals_immutable_v13
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_aggregate_identity_seals
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_aggregate_identity_items_immutable_v13
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_aggregate_identity_items
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

COMMIT;
