import {
  canonicalBytes,
  sha256,
  validateAuthorizationRequest,
} from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import { PolicyEngine } from './policy.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze, validatePolicyDocument } from './validate.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const OPAQUE = /^[A-Za-z0-9._:-]{1,256}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function requestInput(input, actor, policy) {
  const source = cloneBounded(input, { maxBytes: 128 * 1024, maxDepth: 12, maxNodes: 2_000, maxStringBytes: 4_096 });
  const expected = ['requestId', 'tenant', 'repository', 'permission', 'reason', 'resource', 'reference', 'snapshot'].sort();
  const keys = Object.keys(source).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) identityFail('INPUT_INVALID', 'transaction authorization request is invalid');
  return validateAuthorizationRequest({
    schemaVersion: 'ogvcs.authorization/request/v1', requestId: source.requestId,
    actor, tenant: source.tenant, repository: source.repository, permission: source.permission,
    reason: source.reason, resource: source.resource,
    context: {
      reference: source.reference, snapshot: source.snapshot,
      policyGeneration: policy.generation, authorityEpoch: policy.authorityEpoch,
    },
  });
}

function viewShape(value) {
  return deepFreeze(cloneBounded(value, { maxBytes: 16_384, maxDepth: 5, maxNodes: 64, maxStringBytes: 256 }));
}

function canonicalResourceSet(resources) {
  const entries = resources.map((resource) => {
    const value = cloneBounded(resource, { maxBytes: 16_384, maxDepth: 6, maxNodes: 128, maxStringBytes: 4_096 });
    return { value, bytes: canonicalBytes(value) };
  });
  const keys = entries.map(({ bytes }) => bytes.toString('hex'));
  if (new Set(keys).size !== keys.length) identityFail('INPUT_INVALID', 'authorization resources repeat');
  entries.sort((left, right) => Buffer.compare(left.bytes, right.bytes));
  return entries.map(({ value }) => value);
}

export class TransactionAuthorizationAuthority {
  #credentials;
  #participant;
  #views = new WeakMap();

  constructor({ credentialAuthority, participant }) {
    if (!credentialAuthority || typeof credentialAuthority.transactionEvidence !== 'function'
        || typeof credentialAuthority.actorForTransactionEvidence !== 'function'
        || typeof credentialAuthority.authorizeTransactionEvidence !== 'function'
        || !participant || typeof participant.readPolicy !== 'function'
        || typeof participant.transactionId !== 'function'
        || typeof participant.appendDecisionCommitment !== 'function'
        || typeof participant.poison !== 'function') {
      identityFail('INPUT_INVALID', 'transaction authorization dependencies are invalid');
    }
    this.#credentials = credentialAuthority; this.#participant = participant;
  }

  begin({ transaction, credentialToken, request: input }) {
    if (!transaction || typeof transaction !== 'object') identityFail('INPUT_INVALID', 'transaction identity is invalid');
    let transactionId;
    try { transactionId = this.#participant.transactionId(transaction); }
    catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    if (!OPAQUE.test(transactionId ?? '')) identityFail('POLICY_UNAVAILABLE', 'transaction participant returned an invalid identity');
    const policy = this.#policy(transaction, input?.tenant);
    const evidence = this.#credentials.transactionEvidence(credentialToken, { tenant: input?.tenant, policyGeneration: policy.generation });
    if (evidence.authorityEpoch !== policy.authorityEpoch) identityFail('EPOCH_STALE');
    const actor = this.#credentials.actorForTransactionEvidence(evidence);
    const request = requestInput(input, actor, policy);
    const decision = new PolicyEngine(policy).authorize(request, {
      credentialCheck: (candidate) => this.#credentials.authorizeTransactionEvidence(evidence, candidate),
    });
    if (!decision.allowed) identityFail(decision.code === 'DENY_EPOCH_STALE' ? 'EPOCH_STALE' : 'AUTHENTICATION_DENIED');
    const view = viewShape({
      schemaVersion: 'ogvcs.identity-policy/transaction-authorized-view/v1', transactionId,
      evidenceDigest: sha256(canonicalBytes(evidence)), subjectDigest: evidence.subjectDigest,
      authenticatedScopeDigest: evidence.authenticatedScopeDigest,
      requestFingerprint: decision.decisionFingerprint, decisionDigest: sha256(canonicalBytes(decision)),
      tenant: request.tenant, repository: request.repository, permission: request.permission,
      authorityEpoch: evidence.authorityEpoch, credentialGeneration: evidence.credentialGeneration,
      policyGeneration: evidence.policyGeneration, expiresAt: evidence.expiresAt,
    });
    this.#views.set(view, { transaction, evidence, request, policy, commitAttempted: false, committed: false });
    return view;
  }

  permits(view, { transaction, permission, resource }) {
    try { this.#require(view, transaction, permission, resource); return true; }
    catch { return false; }
  }

  authorizeBatch(view, { transaction, permission = view?.permission, resources }) {
    if (!Array.isArray(resources) || resources.length < 1) identityFail('INPUT_INVALID', 'authorization resource batch is invalid');
    if (resources.length > RUNTIME_LIMITS.maxBatchAuthorizationResources) identityFail('LIMIT_EXCEEDED', 'authorization resource batch exceeds its bound');
    const canonicalResources = canonicalResourceSet(resources);
    const authorized = this.#authorizeAll(view, transaction, permission, canonicalResources);
    return deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/authorized-resource-batch/v1',
      transactionId: view.transactionId,
      resourceSetDigest: sha256(canonicalBytes(canonicalResources)),
      items: authorized.map(({ decision }) => Object.freeze({ decisionDigest: sha256(canonicalBytes(decision)) })),
    });
  }

  appendDecisionCommitment(view, { transaction, correlationId, resources, result }) {
    if (!OPAQUE.test(correlationId ?? '') || !Array.isArray(resources) || resources.length < 1
        || resources.length > RUNTIME_LIMITS.maxBatchAuthorizationResources) identityFail('INPUT_INVALID', 'decision commitment input is invalid');
    const state = this.#view(view, transaction);
    if (state.commitAttempted || state.committed) identityFail('STATE_CONFLICT', 'transaction decision commitment already exists');
    const checked = this.#authorizeAll(view, transaction, view.permission, resources).map(({ resource }) => resource);
    const canonicalResources = canonicalResourceSet(checked);
    const resourceSetDigest = sha256(canonicalBytes(canonicalResources));
    const resultValue = cloneBounded(result, { maxBytes: RUNTIME_LIMITS.maxDecisionCommitmentBytes, maxDepth: 8, maxNodes: 256, maxStringBytes: 1_024 });
    const resultDigest = sha256(canonicalBytes(resultValue));
    let record; state.commitAttempted = true;
    try {
      record = this.#participant.appendDecisionCommitment(transaction, {
        schemaVersion: 'ogvcs.identity-policy/transaction-decision-commitment/v1',
        transactionId: view.transactionId, correlationId, tenant: view.tenant, repository: view.repository,
        authorityEpoch: view.authorityEpoch, decisionDigest: view.decisionDigest,
        resourceSetDigest, resultDigest,
      });
    } catch (error) {
      this.#poison(transaction, error);
      throw asIdentityError(error, 'STATE_CONFLICT');
    }
    const commitment = viewShape(record);
    const expected = [
      'schemaVersion', 'commitmentId', 'transactionId', 'correlationId', 'tenant', 'repository',
      'authorityEpoch', 'decisionDigest', 'resourceSetDigest', 'resultDigest', 'sequence', 'previousHash', 'recordHash',
    ].sort();
    const keys = Object.keys(commitment).sort();
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
        || commitment.schemaVersion !== 'ogvcs.identity-policy/transaction-decision-commitment/v1'
        || commitment.transactionId !== view.transactionId || commitment.correlationId !== correlationId
        || commitment.tenant !== view.tenant || commitment.repository !== view.repository
        || commitment.authorityEpoch !== view.authorityEpoch || commitment.decisionDigest !== view.decisionDigest
        || commitment.resourceSetDigest !== resourceSetDigest || commitment.resultDigest !== resultDigest
        || !Number.isSafeInteger(commitment.sequence) || commitment.sequence < 1
        || !(commitment.previousHash === null || SHA256.test(commitment.previousHash)) || !SHA256.test(commitment.recordHash ?? '')) {
      const error = new TypeError('decision commitment record is invalid');
      this.#poison(transaction, error);
      identityFail('POLICY_UNAVAILABLE', 'decision commitment record is invalid', { cause: error });
    }
    state.committed = true;
    return commitment;
  }

  #require(view, transaction, permission, resource) {
    const state = this.#view(view, transaction); const policy = this.#policy(transaction, view.tenant);
    if (policy.generation !== view.policyGeneration || policy.authorityEpoch !== view.authorityEpoch
        || permission !== view.permission) identityFail('AUTHENTICATION_DENIED');
    const actor = this.#credentials.actorForTransactionEvidence(state.evidence);
    const request = validateAuthorizationRequest({
      ...state.request, actor, permission, resource: cloneBounded(resource),
      context: { ...state.request.context, policyGeneration: policy.generation, authorityEpoch: policy.authorityEpoch },
    });
    const decision = new PolicyEngine(policy).authorize(request, {
      credentialCheck: (candidate) => this.#credentials.authorizeTransactionEvidence(state.evidence, candidate),
    });
    if (!decision.allowed) identityFail(decision.code === 'DENY_EPOCH_STALE' ? 'EPOCH_STALE' : 'AUTHENTICATION_DENIED');
    return { resource: request.resource, decision };
  }

  #authorizeAll(view, transaction, permission, resources) {
    const authorized = []; let firstError = null;
    for (const resource of resources) {
      try { authorized.push(this.#require(view, transaction, permission, resource)); }
      catch (error) { authorized.push(null); firstError ??= error; }
    }
    if (firstError !== null) throw asIdentityError(firstError, 'AUTHENTICATION_DENIED');
    return authorized;
  }

  #view(view, transaction) {
    const state = this.#views.get(view);
    if (!state || state.transaction !== transaction) identityFail('AUTHENTICATION_DENIED');
    return state;
  }

  #policy(transaction, tenant) {
    if (!ID.test(tenant ?? '')) identityFail('INPUT_INVALID', 'authorization tenant is invalid');
    let value;
    try { value = this.#participant.readPolicy(transaction, tenant); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'transaction policy read failed closed', { cause: error }); }
    try { return validatePolicyDocument(value); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'transaction policy is invalid', { cause: error }); }
  }

  #poison(transaction, cause) {
    try { this.#participant.poison(transaction, cause); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'authorization transaction could not be poisoned', { cause: error }); }
  }
}
