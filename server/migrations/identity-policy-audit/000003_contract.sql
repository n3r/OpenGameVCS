BEGIN;

CREATE FUNCTION ogvcs_identity.guard_aggregate_plan_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate plans are durable';
    END IF;

    IF ROW(NEW.plan_id, NEW.tenant_id, NEW.repository_id, NEW.credential_id,
           NEW.credential_generation, NEW.presentation_digest, NEW.subject_digest,
           NEW.authenticated_scope_digest, NEW.authority_epoch, NEW.security_epoch,
           NEW.policy_generation, NEW.policy_digest, NEW.metadata_tenant_id,
           NEW.metadata_repository_id,
           NEW.settings_generation, NEW.settings_descriptor_digest, NEW.path_profile,
           NEW.case_mode, NEW.permission, NEW.capability, NEW.reference_name,
           NEW.snapshot_id, NEW.reason, NEW.reason_digest, NEW.issued_at, NEW.expires_at,
           NEW.signer_key_generation, NEW.signer_key_reference,
           NEW.signer_key_fingerprint, NEW.upload_nonce, NEW.handle_mac)
       IS DISTINCT FROM
       ROW(OLD.plan_id, OLD.tenant_id, OLD.repository_id, OLD.credential_id,
           OLD.credential_generation, OLD.presentation_digest, OLD.subject_digest,
           OLD.authenticated_scope_digest, OLD.authority_epoch, OLD.security_epoch,
           OLD.policy_generation, OLD.policy_digest, OLD.metadata_tenant_id,
           OLD.metadata_repository_id,
           OLD.settings_generation, OLD.settings_descriptor_digest, OLD.path_profile,
           OLD.case_mode, OLD.permission, OLD.capability, OLD.reference_name,
           OLD.snapshot_id, OLD.reason, OLD.reason_digest, OLD.issued_at, OLD.expires_at,
           OLD.signer_key_generation, OLD.signer_key_reference,
           OLD.signer_key_fingerprint, OLD.upload_nonce, OLD.handle_mac) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate plan authority binding is immutable';
    END IF;

    IF OLD.state = 'initializing' AND NEW.state = 'uploading' THEN
        IF NEW.item_count <> 0 OR NEW.chunk_count <> 0
           OR NEW.last_resource_key IS NOT NULL
           OR NEW.resource_chain_digest <> OLD.resource_chain_digest
           OR NEW.resource_set_digest IS NOT NULL
           OR NEW.resource_digest_projection_digest IS NOT NULL
           OR NEW.decision_digest IS NOT NULL
           OR NEW.commitment_digest IS NOT NULL OR NEW.receipt_mac IS NOT NULL
           OR NEW.authorized_at IS NOT NULL OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid aggregate initialization transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'uploading' AND NEW.state = 'uploading' THEN
        IF NEW.item_count <= OLD.item_count OR NEW.item_count > OLD.item_count + 1000
           OR NEW.chunk_count <> OLD.chunk_count + 1
           OR NEW.last_resource_key IS NULL
           OR (OLD.last_resource_key IS NOT NULL AND NEW.last_resource_key <= OLD.last_resource_key)
           OR NEW.resource_chain_digest = OLD.resource_chain_digest
           OR NEW.resource_set_digest IS NOT NULL
           OR NEW.resource_digest_projection_digest IS NOT NULL
           OR NEW.decision_digest IS NOT NULL
           OR NEW.commitment_digest IS NOT NULL OR NEW.receipt_mac IS NOT NULL
           OR NEW.authorized_at IS NOT NULL
           OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid aggregate upload transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'uploading' AND NEW.state = 'authorized' THEN
        IF OLD.item_count < 1 OR OLD.chunk_count < 1
           OR NEW.item_count <> OLD.item_count OR NEW.chunk_count <> OLD.chunk_count
           OR NEW.resource_chain_digest <> OLD.resource_chain_digest
           OR NEW.last_resource_key <> OLD.last_resource_key
           OR NEW.resource_set_digest IS NULL
           OR NEW.resource_digest_projection_digest IS NULL
           OR NEW.decision_digest IS NULL
           OR NEW.commitment_digest IS NULL OR NEW.receipt_mac IS NULL
           OR NEW.authorized_at IS NULL
           OR NEW.consumed_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid aggregate authorization transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'authorized' AND NEW.state = 'consumed' THEN
        IF NEW.item_count <> OLD.item_count OR NEW.chunk_count <> OLD.chunk_count
           OR NEW.resource_chain_digest <> OLD.resource_chain_digest
           OR NEW.last_resource_key <> OLD.last_resource_key
           OR NEW.resource_set_digest <> OLD.resource_set_digest
           OR NEW.resource_digest_projection_digest <> OLD.resource_digest_projection_digest
           OR NEW.decision_digest <> OLD.decision_digest
           OR NEW.commitment_digest <> OLD.commitment_digest
           OR NEW.receipt_mac <> OLD.receipt_mac
           OR NEW.authorized_at <> OLD.authorized_at
           OR NEW.consumed_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid aggregate consumption transition';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate plan transition is not permitted';
END
$ogvcs$;

CREATE TRIGGER aggregate_plans_guard
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plans
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_mutation();

CREATE FUNCTION ogvcs_identity.guard_aggregate_signing_key_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE'
       OR ROW(NEW.tenant_id, NEW.key_generation, NEW.authority_epoch,
              NEW.key_reference, NEW.key_fingerprint, NEW.created_at)
          IS DISTINCT FROM
          ROW(OLD.tenant_id, OLD.key_generation, OLD.authority_epoch,
              OLD.key_reference, OLD.key_fingerprint, OLD.created_at) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate signing key binding is immutable';
    END IF;
    IF OLD.state = 'active' AND NEW.state = 'verify-only' AND NEW.retired_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'verify-only' AND NEW.state = 'retired' AND NEW.retired_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate signing key transition is not permitted';
END
$ogvcs$;

CREATE TRIGGER aggregate_signing_keys_guard
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_signing_keys
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_signing_key_mutation();

CREATE FUNCTION ogvcs_identity.guard_compiled_policy_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE'
       OR ROW(NEW.tenant_id, NEW.repository_id, NEW.policy_generation,
              NEW.authority_epoch, NEW.policy_digest, NEW.compiled_digest,
              NEW.path_profile, NEW.case_mode, NEW.compiled_at)
          IS DISTINCT FROM
          ROW(OLD.tenant_id, OLD.repository_id, OLD.policy_generation,
              OLD.authority_epoch, OLD.policy_digest, OLD.compiled_digest,
              OLD.path_profile, OLD.case_mode, OLD.compiled_at) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'compiled policy authority binding is immutable';
    END IF;
    IF OLD.state = 'compiling' AND NEW.state = 'sealed'
       AND OLD.sealed_at IS NULL AND NEW.sealed_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'compiled policy transition is not permitted';
END
$ogvcs$;

CREATE TRIGGER compiled_policies_guard
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policies
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_policy_mutation();

CREATE FUNCTION ogvcs_identity.guard_compiled_projection_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    policy_state text;
BEGIN
    SELECT state INTO STRICT policy_state
    FROM ogvcs_identity.compiled_policies
    WHERE tenant_id = NEW.tenant_id AND repository_id = NEW.repository_id
      AND policy_generation = NEW.policy_generation FOR SHARE;
    IF policy_state <> 'compiling' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'compiled policy projection is sealed';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER compiled_policy_rules_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_rules
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_subjects_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_subjects
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_references_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_references
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_path_prefixes_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_path_prefixes
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_resource_types_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_resource_types
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_permissions_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_permissions
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE TRIGGER compiled_policy_terms_insert_guard
BEFORE INSERT ON ogvcs_identity.compiled_policy_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_compiled_projection_insert();

CREATE FUNCTION ogvcs_identity.guard_aggregate_plan_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    policy_state text;
BEGIN
    SELECT state INTO STRICT policy_state
    FROM ogvcs_identity.compiled_policies
    WHERE tenant_id = NEW.tenant_id AND repository_id = NEW.repository_id
      AND policy_generation = NEW.policy_generation FOR SHARE;
    IF NEW.state <> 'initializing' OR policy_state <> 'sealed' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate plan authority facts are not sealed';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER aggregate_plans_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plans
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_insert();

CREATE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    plan_state text;
BEGIN
    SELECT state INTO STRICT plan_state FROM ogvcs_identity.aggregate_plans
    WHERE plan_id = NEW.plan_id FOR SHARE;
    IF plan_state <> TG_ARGV[0] THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate plan facts are sealed';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER aggregate_plan_subject_terms_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plan_subject_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert('initializing');

CREATE TRIGGER aggregate_plan_scope_terms_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plan_scope_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert('initializing');

CREATE TRIGGER aggregate_plan_scope_path_prefixes_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plan_scope_path_prefixes
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert('initializing');

CREATE TRIGGER aggregate_plan_chunks_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plan_chunks
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert('uploading');

CREATE TRIGGER aggregate_plan_resources_insert_guard
BEFORE INSERT ON ogvcs_identity.aggregate_plan_resources
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_plan_fact_insert('uploading');

CREATE FUNCTION ogvcs_identity.guard_aggregate_commitment_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    plan ogvcs_identity.aggregate_plans%ROWTYPE;
BEGIN
    SELECT * INTO STRICT plan FROM ogvcs_identity.aggregate_plans
    WHERE plan_id = NEW.plan_id FOR SHARE;
    IF ROW(NEW.tenant_id, NEW.repository_id, NEW.subject_digest,
           NEW.authenticated_scope_digest, NEW.credential_generation,
           NEW.authority_epoch, NEW.security_epoch, NEW.policy_generation,
           NEW.policy_digest, NEW.metadata_tenant_id, NEW.metadata_repository_id,
           NEW.settings_generation,
           NEW.settings_descriptor_digest, NEW.path_profile, NEW.case_mode,
           NEW.permission, NEW.capability, NEW.reference_name, NEW.snapshot_id,
           NEW.reason_digest, NEW.resource_count,
           NEW.resource_set_digest, NEW.resource_digest_projection_digest,
           NEW.decision_digest,
           NEW.signer_key_generation, NEW.receipt_mac, NEW.record_digest)
       IS DISTINCT FROM
       ROW(plan.tenant_id, plan.repository_id, plan.subject_digest,
           plan.authenticated_scope_digest, plan.credential_generation,
           plan.authority_epoch, plan.security_epoch, plan.policy_generation,
           plan.policy_digest, plan.metadata_tenant_id, plan.metadata_repository_id,
           plan.settings_generation,
           plan.settings_descriptor_digest, plan.path_profile, plan.case_mode,
           plan.permission, plan.capability, plan.reference_name, plan.snapshot_id,
           plan.reason_digest, plan.item_count,
           plan.resource_set_digest, plan.resource_digest_projection_digest,
           plan.decision_digest,
           plan.signer_key_generation, plan.receipt_mac,
           plan.commitment_digest) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate commitment binding mismatch';
    END IF;
    IF plan.state <> 'authorized' OR plan.item_count < 1 OR plan.chunk_count < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate commitment plan is not sealable';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER aggregate_decision_commitments_binding
BEFORE INSERT ON ogvcs_identity.aggregate_decision_commitments
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_commitment_insert();

CREATE FUNCTION ogvcs_identity.require_aggregate_plan_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF NEW.state IN ('authorized', 'consumed') AND NOT EXISTS (
        SELECT 1 FROM ogvcs_identity.aggregate_decision_commitments commitment
        WHERE commitment.plan_id = NEW.plan_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'authorized aggregate plan lacks commitment';
    END IF;
    IF NEW.state = 'consumed' AND NOT EXISTS (
        SELECT 1 FROM ogvcs_identity.aggregate_plan_consumptions consumption
        WHERE consumption.plan_id = NEW.plan_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'consumed aggregate plan lacks one-use evidence';
    END IF;
    RETURN NULL;
END
$ogvcs$;

CREATE CONSTRAINT TRIGGER aggregate_plans_require_evidence
AFTER INSERT OR UPDATE ON ogvcs_identity.aggregate_plans
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.require_aggregate_plan_evidence();

CREATE FUNCTION ogvcs_identity.guard_aggregate_consumption_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    plan_state text;
BEGIN
    SELECT state INTO STRICT plan_state FROM ogvcs_identity.aggregate_plans
    WHERE plan_id = NEW.plan_id FOR SHARE;
    IF plan_state <> 'authorized' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'aggregate receipt is not consumable';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER aggregate_plan_consumptions_binding
BEFORE INSERT ON ogvcs_identity.aggregate_plan_consumptions
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_aggregate_consumption_insert();

-- Immutable handoffs, compiled generations, uploaded facts, decisions, and
-- consumption evidence may only be replaced by appending a newer generation
-- or minting a new plan.
CREATE TRIGGER repository_contract_roots_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.repository_contract_roots
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER repository_contract_bindings_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.repository_contract_bindings
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER policy_versions_immutable_v3
BEFORE UPDATE OR DELETE ON ogvcs_identity.policy_versions
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_rules_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_rules
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_subjects_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_subjects
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_references_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_references
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_path_prefixes_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_path_prefixes
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_resource_types_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_resource_types
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_permissions_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_permissions
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER compiled_policy_terms_immutable
BEFORE UPDATE OR DELETE ON ogvcs_identity.compiled_policy_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_subject_terms_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_subject_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_scope_terms_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_scope_terms
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_scope_path_prefixes_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_scope_path_prefixes
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_chunks_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_chunks
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_resources_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_resources
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_decision_commitments_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_decision_commitments
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER aggregate_plan_consumptions_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.aggregate_plan_consumptions
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE FUNCTION ogvcs_identity.guard_credential_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE'
       OR ROW(NEW.tenant_id, NEW.credential_id, NEW.credential_generation,
              NEW.presentation_digest, NEW.subject_id, NEW.subject_digest,
              NEW.actor_class, NEW.credential_class, NEW.groups_json,
              NEW.authority_epoch, NEW.issued_at, NEW.expires_at,
              NEW.scope_json, NEW.scope_digest, NEW.created_at,
              NEW.credential_digest_algorithm, NEW.reconstruction_version)
          IS DISTINCT FROM
          ROW(OLD.tenant_id, OLD.credential_id, OLD.credential_generation,
              OLD.presentation_digest, OLD.subject_id, OLD.subject_digest,
              OLD.actor_class, OLD.credential_class, OLD.groups_json,
              OLD.authority_epoch, OLD.issued_at, OLD.expires_at,
              OLD.scope_json, OLD.scope_digest, OLD.created_at,
              OLD.credential_digest_algorithm, OLD.reconstruction_version) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'credential authority facts are immutable';
    END IF;
    IF OLD.state = 'active' AND NEW.state = 'revoked'
       AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND NEW.revoked_at >= OLD.issued_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'credential transition is not permitted';
END
$ogvcs$;

CREATE TRIGGER credentials_guard_v3
BEFORE UPDATE OR DELETE ON ogvcs_identity.credentials
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_credential_mutation();

CREATE FUNCTION ogvcs_identity.guard_authority_promotion()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE' OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'authority state cannot move backward';
    END IF;
    IF NEW.key_generation = OLD.key_generation + 1
       AND NEW.authority_epoch IN (OLD.authority_epoch, OLD.authority_epoch + 1) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'authority promotion must be monotonic and fenced';
END
$ogvcs$;

CREATE TRIGGER authority_states_guard_v3
BEFORE UPDATE OR DELETE ON ogvcs_identity.authority_states
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_authority_promotion();

CREATE FUNCTION ogvcs_identity.guard_current_policy_promotion()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.repository_id <> OLD.repository_id
       OR NEW.policy_generation <= OLD.policy_generation
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'current policy generation cannot move backward';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER current_policies_guard_v3
BEFORE UPDATE OR DELETE ON ogvcs_identity.current_policies
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.guard_current_policy_promotion();

REVOKE ALL ON ALL TABLES IN SCHEMA ogvcs_identity FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ogvcs_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ogvcs_identity FROM PUBLIC;

COMMIT;
