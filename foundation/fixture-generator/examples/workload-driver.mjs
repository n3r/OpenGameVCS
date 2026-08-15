#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import readline from 'node:readline';

const HELP = `Workload-driver black-box consumer

Generates a tiny fixture for every installed profile, reads the public neutral
operation stream, and feeds it to a recording adapter. The example imports no
fixture-generator implementation module and performs no network operations.

Usage:
  node examples/workload-driver.mjs --workspace <relative/path> [--cli <executable>] [--seed <text>]

Options:
  --workspace <path>  New relative directory prefix for generated fixtures
  --cli <path|name>   Installed executable (default: OGVCS_FIXTURE_BIN or ogvcs-fixture)
  --seed <text>       Stable seed prefix (default: workload-driver-example-v1)
  --help              Show this help

Source-checkout smoke run:
  node examples/workload-driver.mjs --cli ./bin/ogvcs-fixture.mjs \
    --workspace example-output/workload-driver
`;

function canonicalJson(value) {
  function ordered(input) {
    if (Array.isArray(input)) return input.map(ordered);
    if (input !== null && typeof input === 'object') {
      return Object.fromEntries(
        Object.keys(input).sort().map((key) => [key, ordered(input[key])]),
      );
    }
    return input;
  }
  return JSON.stringify(ordered(value));
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function portableRelative(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\\')
    || value.includes('\0')
    || path.posix.isAbsolute(value)
    || /^[A-Za-z]:/.test(value)
  ) {
    throw new Error(`${label} must be a portable relative path`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`${label} must not contain empty, dot, or traversal segments`);
  }
  return value;
}

function artifactPath(root, relative, label) {
  portableRelative(relative, label);
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, ...relative.split('/'));
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`${label} escapes its fixture directory`);
  }
  return resolved;
}

function commandSpec(cli) {
  const looksLikeScript = /\.(?:cjs|mjs|js)$/i.test(cli);
  return looksLikeScript
    ? { executable: process.execPath, prefix: [path.resolve(cli)] }
    : { executable: cli, prefix: [] };
}

async function invoke(cli, args) {
  const spec = commandSpec(cli);
  return new Promise((resolve, reject) => {
    const child = spawn(spec.executable, [...spec.prefix, ...args], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`ogvcs-fixture ${args[0]} exited ${code}: ${stderr.trim()}`));
        return;
      }
      try {
        const document = JSON.parse(stdout);
        if (document.ok !== true || document.command !== args[0]) {
          throw new Error(`unexpected CLI result for ${args[0]}`);
        }
        resolve(document.result);
      } catch (error) {
        reject(new Error(`invalid machine output from ogvcs-fixture ${args[0]}: ${error.message}`));
      }
    });
  });
}

const EXPECTED_OPERATION_KINDS = Object.freeze({
  'code-heavy': ['branch', 'copy', 'create', 'delete', 'edit', 'merge', 'rename'],
  'global-studio': [
    'branch-update', 'ci-materialize', 'interrupt', 'lock-acquire', 'lock-conflict',
    'lock-loss', 'network-condition', 'review', 'selective-sync', 'submit',
  ],
  'large-binary': ['copy', 'create', 'edit', 'submit'],
  'unity-like': ['create', 'delete', 'edit', 'move', 'submit'],
  'unreal-like': ['create', 'edit', 'lock-acquire', 'lock-conflict', 'rename', 'submit'],
});

function requiredFields(value, names, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  for (const name of names ?? []) {
    if (!Object.hasOwn(value, name)) throw new Error(`${label} lacks schema-required field ${name}`);
  }
}

function expect(value, label) {
  if (!value) throw new Error(label);
}

function pathMatchesPrefix(logicalPath, prefix) {
  return prefix === '' || logicalPath === prefix || logicalPath.startsWith(`${prefix}/`);
}

function localReference(document, reference) {
  expect(reference.startsWith('#/'), `unsupported public schema reference ${reference}`);
  return reference.slice(2).split('/').reduce((value, segment) => value[segment], document);
}

function parameterSchemasByKind(schema) {
  const branches = schema.properties.operations.items.oneOf;
  return new Map(branches.map((branch) => {
    const operationSchema = localReference(schema, branch.$ref);
    const kind = operationSchema.properties.kind.const;
    return [kind, operationSchema.properties.parameters];
  }));
}

function validateSchemaValue(document, schema, value, label) {
  if (schema.$ref) validateSchemaValue(document, localReference(document, schema.$ref), value, label);
  if (schema.const !== undefined) expect(canonicalJson(value) === canonicalJson(schema.const), `${label} violates const`);
  if (schema.enum) expect(schema.enum.includes(value), `${label} is outside its enum`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array'
      : Number.isSafeInteger(value) ? 'integer' : typeof value;
    expect(types.includes(actual), `${label} must have type ${types.join('|')}`);
  }
  if (typeof value === 'string' && schema.pattern) {
    expect(new RegExp(schema.pattern, 'u').test(value), `${label} violates its pattern`);
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    requiredFields(value, schema.required, label);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        expect(Object.hasOwn(schema.properties ?? {}, key), `${label} has unsupported field ${key}`);
      }
    }
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key]) validateSchemaValue(document, schema.properties[key], child, `${label}.${key}`);
    }
  }
}

class RecordingAdapter {
  constructor(scenario, profileId, operationRequired, publicSchema, parameterSchemas) {
    this.authorizationChecks = 0;
    this.branches = new Map();
    this.committedChanges = new Set();
    this.currentChange = null;
    this.filesByPath = new Map();
    this.fileRevisionsByPath = new Map();
    this.kinds = new Map();
    this.locksByFileId = new Map();
    this.lockRequired = new Set();
    this.networkConditions = new Set();
    this.nextSequence = 0;
    this.operationRequired = operationRequired;
    this.operations = scenario.operations;
    this.parameterSchemas = parameterSchemas;
    this.participants = new Set(scenario.participants.map(({ id }) => id));
    this.profileId = profileId;
    this.publicSchema = publicSchema;
    this.rejectedOutcomes = 0;
    this.revisions = new Map();
    this.retryKeys = new Set();
    this.semanticChecks = 0;
    this.streamChanges = new Set();
    this.stateTransitions = 0;
    this.targets = new Set();
    this.tombstones = new Set();

    expect(this.participants.size === scenario.participants.length, 'scenario participants are not unique');
    this.definedNetworkConditions = new Set(scenario.networkConditions.map(({ id }) => id));
    expect(
      this.definedNetworkConditions.size === scenario.networkConditions.length,
      'scenario network conditions are not unique',
    );
    const identities = scenario.extensions?.['identity-model']?.identities;
    const aclRules = scenario.extensions?.['acl-model']?.rules;
    const stateModel = scenario.extensions?.['state-model'];
    expect(Array.isArray(identities) && identities.length === this.participants.size, 'identity fixture is incomplete');
    expect(Array.isArray(aclRules) && aclRules.length > 0, 'ACL fixture is incomplete');
    const identityIds = new Set(identities.map(({ id }) => id));
    expect(
      identityIds.size === this.participants.size
      && [...this.participants].every((id) => identityIds.has(id)),
      'identity fixture does not bind every participant',
    );
    const identityGroups = new Set(identities.flatMap(({ groups }) => groups));
    for (const rule of aclRules) {
      expect(identityGroups.has(rule.principal), `ACL principal ${rule.principal} has no identity-group member`);
    }
    expect(
      stateModel?.algorithm === 'path-file-id-revision-branch-state-v2',
      'scenario has no executable revision/branch state model',
    );
    for (const change of stateModel.changes) {
      expect(!this.committedChanges.has(change.id), `duplicate initial change ${change.id}`);
      expect(
        change.parent === 'root' || this.committedChanges.has(change.parent),
        `initial change ${change.id} has an undefined parent`,
      );
      expect(change.status === 'committed', `initial change ${change.id} is not committed`);
      this.committedChanges.add(change.id);
    }
    for (const revision of stateModel.revisions) {
      expect(!this.revisions.has(revision.revision), `duplicate initial revision ${revision.revision}`);
      expect(
        this.committedChanges.has(revision.changeId)
        && revision.revision.startsWith(`${revision.changeId}-r`),
        `initial revision ${revision.revision} has an undefined change`,
      );
      this.revisions.set(revision.revision, revision.changeId);
    }
    for (const branch of stateModel.branches) {
      expect(!this.branches.has(branch.name), `duplicate initial branch ${branch.name}`);
      expect(
        branch.head === null || this.revisions.has(branch.head),
        `initial branch ${branch.name} has an undefined head`,
      );
      this.branches.set(branch.name, branch.head);
    }
    expect(this.branches.has('main'), 'state model does not define a main branch');
    for (const file of stateModel.files) {
      expect(!this.filesByPath.has(file.logicalPath), `duplicate initial path ${file.logicalPath}`);
      expect(this.revisions.has(file.revision), `initial path ${file.logicalPath} has an undefined revision`);
      this.filesByPath.set(file.logicalPath, file.fileId);
      this.fileRevisionsByPath.set(file.logicalPath, file.revision);
    }
    this.aclRules = aclRules;
    this.aclRuleCount = aclRules.length;
    this.identities = new Map(identities.map((identity) => [identity.id, new Set(identity.groups)]));
    this.identityCount = identities.length;
  }

  accept(operation) {
    if (operation.sequence !== this.nextSequence) {
      throw new Error(`operation sequence ${operation.sequence} is not ${this.nextSequence}`);
    }
    requiredFields(operation, this.operationRequired, `operation ${operation.sequence}`);
    const expectedOperation = this.operations[this.nextSequence];
    if (canonicalJson(operation) !== canonicalJson(expectedOperation)) {
      throw new Error(`operation stream diverges from scenario envelope at ${operation.sequence}`);
    }
    expect(this.participants.has(operation.actor), `operation ${operation.sequence} has an unknown actor`);
    portableRelative(operation.target, `operation ${operation.sequence} target`);
    const parameters = operation.parameters;
    const parameterSchema = this.parameterSchemas.get(operation.kind);
    expect(parameterSchema !== undefined, `operation ${operation.sequence} kind is absent from the public schema`);
    validateSchemaValue(
      this.publicSchema,
      parameterSchema,
      parameters,
      `operation ${operation.sequence}.parameters`,
    );
    expect(/^change-[0-9]{8}$/.test(parameters['change-id']), `operation ${operation.sequence} has no stable change ID`);
    expect(/^[0-9a-f]{32}$/.test(parameters['retry-key']), `operation ${operation.sequence} has no retry key`);
    expect(!this.retryKeys.has(parameters['retry-key']), `operation ${operation.sequence} reuses a retry key`);
    this.retryKeys.add(parameters['retry-key']);
    if (parameters['change-id'] !== this.currentChange) {
      expect(
        !this.streamChanges.has(parameters['change-id']),
        `operation stream returns to closed change ${parameters['change-id']}`,
      );
      this.streamChanges.add(parameters['change-id']);
      this.currentChange = parameters['change-id'];
    }
    this.validateAuthorization(operation);
    this.validateFileState(operation);

    this.kinds.set(operation.kind, (this.kinds.get(operation.kind) ?? 0) + 1);
    if (operation.networkCondition) {
      expect(
        this.definedNetworkConditions.has(operation.networkCondition),
        `operation ${operation.sequence} names an undefined network condition`,
      );
      this.networkConditions.add(operation.networkCondition);
    }
    if (operation.target) this.targets.add(operation.target);
    this.validateKind(operation);
    this.nextSequence += 1;
  }

  validateAuthorization(operation) {
    const groups = this.identities.get(operation.actor);
    const match = this.aclRules.find((rule) => (
      rule.actions.includes(operation.authorization.action)
      && groups.has(rule.principal)
      && pathMatchesPrefix(operation.target, rule.pathPrefix)
    ));
    expect(match !== undefined, `operation ${operation.sequence} is denied by the declared ACL`);
    expect(operation.authorization.decision === 'allow', `operation ${operation.sequence} misstates its ACL decision`);
    expect(
      operation.authorization.matchedPrincipal === match.principal
      && operation.authorization.matchedPathPrefix === match.pathPrefix,
      `operation ${operation.sequence} authorization does not name the first matching ACL rule`,
    );
    this.authorizationChecks += 1;
  }

  defineRevision(revision, changeId, label) {
    expect(
      typeof revision === 'string' && revision.startsWith(`${changeId}-r`),
      `${label} does not belong to ${changeId}`,
    );
    expect(!this.revisions.has(revision), `${label} redefines revision ${revision}`);
    this.revisions.set(revision, changeId);
  }

  requireRevision(revision, label) {
    expect(this.revisions.has(revision), `${label} references undefined revision ${revision}`);
    return revision;
  }

  validateFileState(operation) {
    const effect = operation.fileId;
    const current = this.filesByPath.get(operation.target);
    const currentRevision = this.fileRevisionsByPath.get(operation.target);
    const parameters = operation.parameters;
    const changeId = parameters['change-id'];
    const success = operation.expectedOutcome.status === 'succeeded';
    if (!success) this.rejectedOutcomes += 1;
    if (operation.kind === 'create') {
      expect(current === undefined && effect.source === null, `create ${operation.sequence} does not start at an absent path`);
      expect(/^[0-9a-f]{32}$/.test(effect.result) && effect.semantics === 'created', 'create lacks new FileID semantics');
      if (success) {
        this.defineRevision(parameters['result-revision'], changeId, `create ${operation.sequence}`);
        this.filesByPath.set(operation.target, effect.result);
        this.fileRevisionsByPath.set(operation.target, parameters['result-revision']);
        this.branches.set('main', parameters['result-revision']);
      }
    } else if (operation.kind === 'edit') {
      expect(current === effect.source, `edit ${operation.sequence} source FileID is stale`);
      expect(effect.result === effect.source && effect.semantics === 'modified', 'edit must preserve FileID');
      expect(
        currentRevision === parameters['base-revision'],
        `edit ${operation.sequence} names a stale base revision`,
      );
      this.requireRevision(parameters['base-revision'], `edit ${operation.sequence}`);
      if (success) {
        this.defineRevision(parameters['result-revision'], changeId, `edit ${operation.sequence}`);
        this.fileRevisionsByPath.set(operation.target, parameters['result-revision']);
        this.branches.set('main', parameters['result-revision']);
      }
    } else if (operation.kind === 'copy') {
      expect(current === effect.source, `copy ${operation.sequence} source FileID is stale`);
      expect(!this.filesByPath.has(operation.relatedTarget), `copy ${operation.sequence} destination already exists`);
      expect(effect.result !== effect.source && effect.semantics === 'copied', 'copy must fork a new FileID');
      if (success) {
        this.filesByPath.set(operation.relatedTarget, effect.result);
        this.fileRevisionsByPath.set(operation.relatedTarget, currentRevision);
      }
    } else if (operation.kind === 'move' || operation.kind === 'rename') {
      expect(current === effect.source, `${operation.kind} ${operation.sequence} source FileID is stale`);
      expect(!this.filesByPath.has(operation.relatedTarget), `${operation.kind} ${operation.sequence} destination already exists`);
      const expectedSemantics = operation.kind === 'move' ? 'moved' : 'renamed';
      expect(effect.result === effect.source && effect.semantics === expectedSemantics, `${operation.kind} must preserve FileID`);
      if (success) {
        this.filesByPath.delete(operation.target);
        this.fileRevisionsByPath.delete(operation.target);
        this.filesByPath.set(operation.relatedTarget, effect.result);
        this.fileRevisionsByPath.set(operation.relatedTarget, currentRevision);
      }
    } else if (operation.kind === 'delete') {
      expect(current === effect.source, `delete ${operation.sequence} source FileID is stale`);
      expect(effect.result === null && effect.semantics === 'deleted', 'delete must leave a FileID tombstone');
      expect(
        currentRevision === parameters['base-revision'],
        `delete ${operation.sequence} names a stale base revision`,
      );
      this.requireRevision(parameters['base-revision'], `delete ${operation.sequence}`);
      if (success) {
        this.filesByPath.delete(operation.target);
        this.fileRevisionsByPath.delete(operation.target);
        this.tombstones.add(effect.source);
      }
    } else if (effect.semantics === 'tombstone-observed') {
      expect(current === undefined && effect.result === null && this.tombstones.has(effect.source), `operation ${operation.sequence} names no known tombstone`);
    } else {
      expect(current === effect.source && effect.result === effect.source, `operation ${operation.sequence} observes a stale FileID`);
    }
    this.stateTransitions += 1;
  }

  validateKind(operation) {
    const parameters = operation.parameters;
    const changeId = parameters['change-id'];
    if (operation.relatedTarget) portableRelative(operation.relatedTarget, `${operation.kind} related target`);

    if (operation.kind === 'create') {
      expect(
        this.revisions.get(parameters['result-revision']) === changeId,
        `create ${operation.sequence} has an incoherent result revision`,
      );
    }
    else if (operation.kind === 'edit') {
      expect(
        this.revisions.get(parameters['result-revision']) === changeId,
        `edit ${operation.sequence} has an incoherent result revision`,
      );
      expect(parameters['delta-kind'] === 'semantic-v2', 'edit does not describe a semantic v2 delta');
    } else if (['copy', 'move', 'rename'].includes(operation.kind)) {
      expect(typeof parameters['preserve-file-id'] === 'boolean', `${operation.kind} lacks identity semantics`);
      const targetRoot = operation.target.split('/')[0];
      expect(
        operation.relatedTarget?.startsWith(`${targetRoot}/Changes/${operation.kind}/`),
        `${operation.kind} lacks a coherent related target`,
      );
    } else if (operation.kind === 'delete') {
      expect(parameters.tombstone === true, 'delete is not represented as a tombstone');
    } else if (operation.kind === 'branch') {
      expect(
        operation.relatedTarget === `branches/${parameters['target-branch']}`,
        `branch ${operation.sequence} target branch is incoherent`,
      );
      const sourceHead = this.branches.get(parameters['source-branch']);
      expect(sourceHead !== undefined, `branch ${operation.sequence} has no source branch`);
      this.requireRevision(parameters['from-revision'], `branch ${operation.sequence}`);
      expect(
        sourceHead === parameters['from-revision'],
        `branch ${operation.sequence} does not start from the source head`,
      );
      expect(
        !this.branches.has(parameters['target-branch']),
        `branch ${operation.sequence} reuses target ${parameters['target-branch']}`,
      );
      if (operation.expectedOutcome.status === 'succeeded') {
        this.branches.set(parameters['target-branch'], parameters['from-revision']);
      }
    } else if (operation.kind === 'merge') {
      expect(operation.relatedTarget === 'branches/main', 'merge does not target main');
      expect(parameters.strategy === 'three-way', 'merge lacks three-way semantics');
      const sourceHead = this.branches.get(parameters['source-branch']);
      const targetHead = this.branches.get(parameters['target-branch']);
      expect(sourceHead !== undefined, `merge ${operation.sequence} has no source branch`);
      expect(targetHead !== undefined, `merge ${operation.sequence} has no target branch`);
      this.requireRevision(parameters['common-base'], `merge ${operation.sequence}`);
      expect(
        sourceHead === parameters['common-base'],
        `merge ${operation.sequence} common base is not the source head`,
      );
      if (operation.expectedOutcome.status === 'succeeded') {
        this.branches.set(parameters['target-branch'], sourceHead);
      }
    } else if (operation.kind === 'lock-acquire') {
      expect(/^[0-9a-f]{32}$/.test(parameters['lock-id']), 'lock acquisition lacks a stable lock ID');
      this.locksByFileId.set(operation.fileId.source, {
        holder: operation.actor,
        lockId: parameters['lock-id'],
        target: operation.target,
      });
      this.lockRequired.add(operation.fileId.source);
    } else if (operation.kind === 'lock-conflict') {
      const lock = this.locksByFileId.get(operation.fileId.source);
      expect(lock !== undefined, 'lock conflict has no preceding acquisition in its change');
      expect(lock.lockId === parameters['lock-id'] && lock.target === operation.target, 'lock conflict targets another lock');
      expect(parameters.holder === lock.holder, 'lock conflict names the wrong holder');
      expect(parameters.contender === operation.actor && parameters.outcome === 'denied', 'lock conflict is not a denied contender');
    } else if (operation.kind === 'lock-loss') {
      const lock = this.locksByFileId.get(operation.fileId.source);
      expect(lock !== undefined && lock.lockId === parameters['lock-id'], 'lock loss has no matching acquisition');
      expect(parameters.recovery === 'shelve-local-work', 'lock loss lacks recovery semantics');
      expect(parameters['submit-policy'] === 'reject-until-reacquired', 'lock loss does not gate later submit success');
      this.locksByFileId.delete(operation.fileId.source);
    } else if (operation.kind === 'submit') {
      expect(parameters.atomic === true, 'submit is not marked atomic');
      expect(
        parameters['parent-change'] === 'root' || this.committedChanges.has(parameters['parent-change']),
        `submit ${operation.sequence} has an undefined parent change`,
      );
      const lock = this.locksByFileId.get(operation.fileId.source);
      if (this.lockRequired.has(operation.fileId.source) && lock === undefined) {
        expect(
          operation.expectedOutcome.status === 'rejected' && operation.expectedOutcome.code === 'lock-not-held',
          'submit after lock loss must be explicitly rejected or follow reacquisition',
        );
      } else {
        expect(operation.expectedOutcome.status === 'succeeded', 'submit with valid state is not expected to succeed');
      }
      if (operation.expectedOutcome.status === 'succeeded') {
        expect(!this.committedChanges.has(changeId), `submit ${operation.sequence} repeats a committed change`);
        this.committedChanges.add(changeId);
      }
    } else if (operation.kind === 'branch-update') {
      expect(
        operation.relatedTarget === `branches/${parameters['target-branch']}`,
        `branch update ${operation.sequence} target branch is incoherent`,
      );
      const sourceHead = this.branches.get(parameters['source-branch']);
      const targetHead = this.branches.get(parameters['target-branch']);
      expect(sourceHead !== undefined, `branch update ${operation.sequence} has no source branch`);
      expect(targetHead !== undefined, `branch update ${operation.sequence} has no target branch`);
      this.requireRevision(parameters['expected-head'], `branch update ${operation.sequence}`);
      expect(
        targetHead === parameters['expected-head'],
        `branch update ${operation.sequence} expected head is stale`,
      );
      if (operation.expectedOutcome.status === 'succeeded') {
        this.branches.set(parameters['target-branch'], sourceHead);
      }
    } else if (operation.kind === 'review') {
      expect(['approved', 'changes-requested'].includes(parameters.decision), 'review decision is invalid');
      expect(
        Array.isArray(parameters.reviewers) && parameters.reviewers.every((id) => this.participants.has(id)),
        'review references an unknown participant',
      );
    } else if (operation.kind === 'selective-sync') {
      expect(Array.isArray(parameters.includes) && parameters.includes.length > 0, 'selective sync has no include set');
      expect(Array.isArray(parameters.excludes) && parameters.excludes.length > 0, 'selective sync has no exclude set');
      this.requireRevision(parameters['revision-selector'], `selective sync ${operation.sequence}`);
    } else if (operation.kind === 'ci-materialize') {
      expect(parameters['clean-workspace'] === true, 'CI materialization is not clean');
      expect(['linux', 'macos', 'windows'].includes(parameters.platform), 'CI materialization platform is invalid');
      this.requireRevision(parameters.revision, `CI materialization ${operation.sequence}`);
    } else if (operation.kind === 'interrupt') {
      expect(parameters['after-bytes'] > 0, 'interruption has no byte boundary');
      expect(parameters.recovery === 'resume-with-retry-key', 'interruption lacks retry semantics');
    } else if (operation.kind === 'network-condition') {
      expect(operation.networkCondition !== undefined, 'network operation has no link profile');
      expect(parameters.transition === 'apply-link-profile', 'network operation has no transition semantics');
    }
    this.semanticChecks += 1;
  }

  summary() {
    for (const kind of EXPECTED_OPERATION_KINDS[this.profileId] ?? []) {
      if (!this.kinds.has(kind)) throw new Error(`${this.profileId} scenario lacks expected ${kind} operation`);
    }
    return {
      aclRuleCount: this.aclRuleCount,
      authorizationChecks: this.authorizationChecks,
      branchCount: this.branches.size,
      committedChangeCount: this.committedChanges.size,
      identityCount: this.identityCount,
      kinds: Object.fromEntries([...this.kinds].sort(([left], [right]) => compareText(left, right))),
      networkConditionsUsed: [...this.networkConditions].sort(),
      operationCount: this.nextSequence,
      rejectedOutcomes: this.rejectedOutcomes,
      revisionCount: this.revisions.size,
      semanticChecks: this.semanticChecks,
      stateTransitions: this.stateTransitions,
      targetCount: this.targets.size,
    };
  }
}

async function driveOperations(fixtureRoot, scenario, profileId, operationRequired, publicSchema, parameterSchemas) {
  const operationsPath = artifactPath(fixtureRoot, 'operations.ndjson', 'operation stream path');
  const adapter = new RecordingAdapter(
    scenario,
    profileId,
    operationRequired,
    publicSchema,
    parameterSchemas,
  );
  const input = createReadStream(operationsPath, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.length !== 0) adapter.accept(JSON.parse(line));
  }
  return adapter.summary();
}

async function main() {
  const { values } = parseArgs({
    options: {
      cli: { type: 'string' },
      help: { short: 'h', type: 'boolean' },
      seed: { type: 'string' },
      workspace: { type: 'string' },
    },
    strict: true,
  });
  if (values.help) {
    process.stdout.write(HELP);
    return;
  }
  if (!values.workspace) throw new Error('--workspace is required; it must name a new relative path');
  const workspace = portableRelative(values.workspace, '--workspace');
  const cli = values.cli ?? process.env.OGVCS_FIXTURE_BIN ?? 'ogvcs-fixture';
  const seed = values.seed ?? 'workload-driver-example-v1';

  const schemaPath = fileURLToPath(new URL('../schemas/OperationScenario.schema.json', import.meta.url));
  const scenarioSchema = JSON.parse(await readFile(schemaPath, 'utf8'));
  const allowedKinds = new Set(scenarioSchema.properties?.operations?.items?.properties?.kind?.enum ?? []);
  if (allowedKinds.size === 0) throw new Error('public operation schema has no operation-kind contract');
  const parameterSchemas = parameterSchemasByKind(scenarioSchema);
  expect(parameterSchemas.size === allowedKinds.size, 'public operation schema does not discriminate every kind');

  const listed = await invoke(cli, ['list']);
  const profiles = [...listed.profiles].sort((left, right) => compareText(left.id, right.id));
  const summaries = [];
  for (const profile of profiles) {
    const destination = `${workspace}/${profile.id}`;
    const requestFlags = [
      '--profile', profile.id,
      '--profile-version', profile.version,
      '--seed', `${seed}-${profile.id}`,
      '--destination', destination,
      '--path-count', '32',
      '--history-operations', '20',
      '--large-file-bytes', '8192',
      '--max-depth', '5',
      '--checkpoint-every', '4',
      '--materialization', 'index-only',
      '--materialized-path-limit', '0',
      '--large-file-mode', 'virtual',
    ];
    if (profile.id === 'unity-like') requestFlags.push('--negative-cases');
    const generated = await invoke(cli, ['generate', ...requestFlags]);
    const verification = await invoke(cli, ['verify', destination, '--deep']);
    const fixtureRoot = path.resolve(process.cwd(), ...destination.split('/'));
    const manifest = JSON.parse(await readFile(path.join(fixtureRoot, 'manifest.json'), 'utf8'));
    const scenarioPath = artifactPath(
      fixtureRoot,
      manifest.operationScenario.path,
      'manifest.operationScenario.path',
    );
    const scenario = JSON.parse(await readFile(scenarioPath, 'utf8'));
    if (
      manifest.schemaVersions.scenario
      !== scenarioSchema.properties.schemaVersion.const
    ) {
      throw new Error(`manifest does not bind the public scenario schema for ${profile.id}`);
    }
    const driven = await driveOperations(
      fixtureRoot,
      scenario,
      profile.id,
      scenarioSchema.properties.operations.items.required,
      scenarioSchema,
      parameterSchemas,
    );
    for (const kind of Object.keys(driven.kinds)) {
      if (!allowedKinds.has(kind)) throw new Error(`public schema does not define operation kind ${kind}`);
    }
    if (
      generated.manifestDigest !== manifest.manifestDigest
      || verification.manifestDigest !== manifest.manifestDigest
      || scenario.operations.length !== driven.operationCount
      || manifest.counts.operations !== driven.operationCount
    ) {
      throw new Error(`public workload artifacts disagree for profile ${profile.id}`);
    }
    summaries.push({
      aclRuleCount: driven.aclRuleCount,
      authorizationChecks: driven.authorizationChecks,
      branchCount: driven.branchCount,
      committedChangeCount: driven.committedChangeCount,
      identityCount: driven.identityCount,
      kinds: driven.kinds,
      manifestDigest: manifest.manifestDigest,
      networkConditionCount: scenario.networkConditions.length,
      networkConditionsUsed: driven.networkConditionsUsed,
      operationCount: driven.operationCount,
      operationDigest: manifest.digests.operations,
      participantCount: scenario.participants.length,
      profile: `${profile.id}@${profile.version}`,
      requestDigest: manifest.requestDigest,
      rejectedOutcomes: driven.rejectedOutcomes,
      revisionCount: driven.revisionCount,
      scenarioDigest: scenario.digest,
      semanticChecks: driven.semanticChecks,
      stateTransitions: driven.stateTransitions,
      targetCount: driven.targetCount,
      verified: verification.verified,
    });
  }

  process.stdout.write(`${canonicalJson({
    consumer: 'ogvcs-workload-driver-example/v1',
    profiles: summaries,
    schema: scenarioSchema.$id,
  })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${canonicalJson({ error: error.message, ok: false })}\n`);
  process.exitCode = 1;
});
