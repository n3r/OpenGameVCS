import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const prdRoot = path.dirname(fileURLToPath(import.meta.url));
const roadmapPath = path.join(prdRoot, 'ROADMAP.md');
const prdFilePattern = /^(OGVCS-\d{3})-.+\.md$/;
const requirementPattern = /^- \*\*(OGVCS-\d{3}-(FR|NFR|AC)-(\d{2})):\*\*/gm;
const requiredMetadata = [
  'Status',
  'Release',
  'Priority',
  'Owner',
  'Depends on',
  'Blocks',
  'Source',
  'Last updated',
];
const requiredHeadings = [
  '## Outcome',
  '## Problem',
  '## Scope',
  '### In scope',
  '### Out of scope',
  '## Users and journeys',
  '## Requirements',
  '### Functional',
  '### Quality attributes',
  '## Interfaces and data',
  '## Development plan',
  '## Acceptance criteria',
  '## Verification plan',
  '## Telemetry and operations',
  '## Rollout and rollback',
  '## Risks and mitigations',
  '## Completion evidence',
];
const evidenceLabels = [
  'Implementation changes',
  'Test and benchmark results',
  'Security/reliability review',
  'Documentation/runbooks',
  'Rollout result',
];
const allowedTodoStatuses = new Set(['Todo', 'In development', 'Validation', 'Blocked']);
const releases = new Map([
  ['R0 — Engineering Foundation', 0],
  ['R1 — Developer Preview', 1],
  ['R2 — Studio Alpha', 2],
  ['R3 — Production Beta', 3],
  ['R4 — Ecosystem', 4],
]);
const allowedPriorities = new Set(['P0', 'P1', 'P2']);
const placeholderEvidence = /^(?:tbd|todo|none|n\/a|na|pending|unavailable|-+)\.?$/i;
const errors = [];

function addError(location, message) {
  errors.push(`${location}: ${message}`);
}

function readMetadataValues(body, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return [...body.matchAll(new RegExp(`^\\*\\*${escaped}:\\*\\* (.+?)\\s*$`, 'gm'))]
    .map((match) => match[1]);
}

function stripFencedCode(body) {
  let inFence = false;
  return body
    .split('\n')
    .map((line) => {
      if (/^\s*```/.test(line)) {
        inFence = !inFence;
        return '';
      }
      return inFence ? '' : line;
    })
    .join('\n');
}

function collectHeadings(body) {
  const visible = stripFencedCode(body);
  return visible
    .split('\n')
    .map((line) => line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/))
    .filter(Boolean)
    .map((match) => `${match[1]} ${match[2]}`);
}

function extractSection(body, heading, nextHeading) {
  const escapedHeading = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const escapedNext = nextHeading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return body.match(new RegExp(`^${escapedHeading}\\s*$([\\s\\S]*?)^${escapedNext}\\s*$`, 'm'))?.[1] ?? '';
}

function isValidIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value ?? '')) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}

function parseExplicitIds(value, location, field) {
  if (value === 'None') return [];
  if (!value) return [];

  const ids = value.split(',').map((item) => item.trim());
  for (const id of ids) {
    if (!/^OGVCS-\d{3}$/.test(id)) {
      addError(location, `${field} contains invalid direct ID ${JSON.stringify(id)}`);
    }
  }
  if (new Set(ids).size !== ids.length) {
    addError(location, `${field} contains a duplicate ID`);
  }
  return ids.filter((id) => /^OGVCS-\d{3}$/.test(id));
}

function expandRoadmapDependencies(value, location) {
  if (value === 'None') return [];

  const ids = [];
  for (const item of value.split(',')) {
    const token = item.trim();
    const match = token.match(/^(?:OGVCS-)?(\d{3})(?:[–-](?:OGVCS-)?(\d{3}))?$/);
    if (!match) {
      addError(location, `invalid roadmap dependency token ${JSON.stringify(token)}`);
      continue;
    }

    const first = Number(match[1]);
    const last = Number(match[2] ?? match[1]);
    if (last < first) {
      addError(location, `descending dependency range ${JSON.stringify(token)}`);
      continue;
    }
    for (let number = first; number <= last; number += 1) {
      ids.push(`OGVCS-${String(number).padStart(3, '0')}`);
    }
  }
  if (new Set(ids).size !== ids.length) addError(location, 'roadmap dependency cell contains duplicate/overlapping IDs');
  return ids;
}

function sameOrderedValues(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validateLocalLinks(filePath, body) {
  for (const match of body.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (/^(?:https?:|mailto:|#)/.test(target)) continue;

    const localTarget = target.split('#')[0];
    if (localTarget && !fs.existsSync(path.resolve(path.dirname(filePath), localTarget))) {
      addError(path.relative(prdRoot, filePath), `broken local link ${target}`);
    }
  }
}

function collectPrds() {
  const records = new Map();
  const requirementOwners = new Map();

  for (const folder of ['todo', 'done']) {
    const folderPath = path.join(prdRoot, folder);
    for (const filename of fs.readdirSync(folderPath).sort()) {
      if (folder === 'done' && filename === 'README.md') continue;
      const filenameMatch = filename.match(prdFilePattern);
      if (!filenameMatch) {
        if (filename.endsWith('.md')) addError(`${folder}/${filename}`, 'unexpected Markdown file; PRDs must use OGVCS-NNN-slug.md');
        continue;
      }

      const id = filenameMatch[1];
      const location = `${folder}/${filename}`;
      const filePath = path.join(folderPath, filename);
      const body = fs.readFileSync(filePath, 'utf8');
      const visibleBody = stripFencedCode(body);
      if (records.has(id)) addError(location, `duplicate PRD ID; also in ${records.get(id).location}`);

      const metadata = {};
      for (const key of requiredMetadata) {
        const values = readMetadataValues(visibleBody, key);
        if (values.length === 0) addError(location, `missing metadata field ${key}`);
        if (values.length > 1) addError(location, `metadata field ${key} appears ${values.length} times`);
        metadata[key] = values[0];
      }

      if (!body.startsWith(`# ${id} — `)) addError(location, 'title does not match filename ID');
      const headings = collectHeadings(body);
      let priorHeadingIndex = -1;
      for (const heading of requiredHeadings) {
        const indices = headings
          .map((candidate, index) => candidate === heading ? index : -1)
          .filter((index) => index >= 0);
        if (indices.length === 0) {
          addError(location, `missing heading ${heading}`);
        } else if (indices.length > 1) {
          addError(location, `heading ${heading} appears ${indices.length} times`);
        } else if (indices[0] <= priorHeadingIndex) {
          addError(location, `heading ${heading} is out of required order`);
        } else {
          priorHeadingIndex = indices[0];
        }
      }

      if (metadata.Release && !releases.has(metadata.Release)) {
        addError(location, `unsupported release ${metadata.Release}`);
      }
      if (metadata.Priority && !allowedPriorities.has(metadata.Priority)) {
        addError(location, `unsupported priority ${metadata.Priority}`);
      }
      if (metadata['Last updated'] && !isValidIsoDate(metadata['Last updated'])) {
        addError(location, `Last updated must be a real YYYY-MM-DD date, found ${metadata['Last updated']}`);
      }
      if (metadata.Owner && /^(?:TBD|TODO|None)$/i.test(metadata.Owner)) {
        addError(location, `invalid Owner placeholder ${metadata.Owner}; use Unassigned while Todo`);
      }
      if (metadata.Source && !/^\[[^\]]+\]\([^)]+\)$/.test(metadata.Source)) {
        addError(location, 'Source must be one Markdown link');
      }

      const developmentPlan = extractSection(visibleBody, '## Development plan', '## Acceptance criteria');
      const developmentSlices = [...developmentPlan.matchAll(/^\d+\.\s+\S/gm)];
      if (developmentSlices.length < 3) {
        addError(location, 'Development plan must contain at least three named implementation slices');
      }
      const acceptanceCriteria = extractSection(visibleBody, '## Acceptance criteria', '## Verification plan');
      const requirementsSection = extractSection(visibleBody, '## Requirements', '## Interfaces and data');
      const interfacesSection = extractSection(visibleBody, '## Interfaces and data', '## Development plan');
      const verificationSection = extractSection(visibleBody, '## Verification plan', '## Telemetry and operations');

      if (folder === 'done' && metadata.Status !== 'Done') {
        addError(location, `done PRD must have Status: Done, found ${metadata.Status}`);
      }
      if (folder === 'todo' && metadata.Status && !allowedTodoStatuses.has(metadata.Status)) {
        addError(location, `todo PRD has unsupported status ${metadata.Status}`);
      }
      if (
        folder === 'todo'
        && ['In development', 'Validation', 'Blocked'].includes(metadata.Status)
        && metadata.Owner === 'Unassigned'
      ) {
        addError(location, `${metadata.Status} PRD must have an owner`);
      }
      if (folder === 'done' && metadata.Owner === 'Unassigned') {
        addError(location, 'done PRD must have a named owner');
      }

      const requirements = { FR: [], NFR: [], AC: [] };
      for (const match of visibleBody.matchAll(requirementPattern)) {
        const [label, type, numberText] = match.slice(1);
        const labelId = label.slice(0, 9);
        if (labelId !== id) addError(location, `foreign requirement label ${label}`);
        if (requirementOwners.has(label)) {
          addError(location, `duplicate requirement label ${label}; also in ${requirementOwners.get(label)}`);
        } else {
          requirementOwners.set(label, location);
        }
        requirements[type].push(Number(numberText));
      }

      for (const [type, numbers] of Object.entries(requirements)) {
        const ordered = [...new Set(numbers)].sort((left, right) => left - right);
        if (ordered.length === 0) addError(location, `has no ${type} requirement IDs`);
        for (let expected = 1; expected <= ordered.length; expected += 1) {
          if (ordered[expected - 1] !== expected) {
            addError(location, `${type} requirement IDs must be contiguous from 01`);
            break;
          }
        }
      }

      if (folder === 'done') {
        const evidence = visibleBody.match(/^## Completion evidence\s*$([\s\S]*)/m)?.[1] ?? '';
        for (const label of evidenceLabels) {
          const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const matches = [...evidence.matchAll(new RegExp(`^- ${escaped}:\\s*(.+?)\\s*$`, 'gm'))];
          const value = matches[0]?.[1];
          if (matches.length > 1) addError(location, `completion evidence repeats ${label}`);
          if (!value || placeholderEvidence.test(value)) {
            addError(location, `completion evidence is blank for ${label}`);
          } else if (!/\[[^\]]+\]\([^)]+\)/.test(value)) {
            addError(location, `completion evidence for ${label} must contain a Markdown link`);
          }
        }
        for (const number of requirements.AC) {
          const acceptanceId = `${id}-AC-${String(number).padStart(2, '0')}`;
          const escaped = acceptanceId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const matches = [...evidence.matchAll(new RegExp(`^- ${escaped}:\\s*(.+?)\\s*$`, 'gm'))];
          const value = matches[0]?.[1];
          if (matches.length > 1) addError(location, `completion evidence repeats ${acceptanceId}`);
          if (!value || placeholderEvidence.test(value) || !/\[[^\]]+\]\([^)]+\)/.test(value)) {
            addError(location, `completion evidence must link proof for ${acceptanceId}`);
          }
        }
      }

      validateLocalLinks(filePath, body);
      records.set(id, {
        id,
        folder,
        filename,
        location,
        metadata,
        releaseOrdinal: releases.get(metadata.Release),
        dependsOn: parseExplicitIds(metadata['Depends on'], location, 'Depends on'),
        blocks: parseExplicitIds(metadata.Blocks, location, 'Blocks'),
        mentions: new Set(visibleBody.match(/OGVCS-\d{3}/g) ?? []),
        implementationReferences: new Set(
          `${developmentPlan}\n${acceptanceCriteria}`.match(/OGVCS-\d{3}/g) ?? [],
        ),
        contractReferences: new Set(
          `${requirementsSection}\n${interfacesSection}\n${verificationSection}`.match(/OGVCS-\d{3}/g) ?? [],
        ),
      });
    }
  }

  return { records, requirementCount: requirementOwners.size };
}

function collectRoadmapRows() {
  const body = fs.readFileSync(roadmapPath, 'utf8');
  const rows = new Map();
  let release;
  let portfolioOrder = 0;

  for (const line of body.split('\n')) {
    const releaseMatch = line.match(/^### (R\d) —/);
    if (releaseMatch) release = releaseMatch[1];

    const row = line.match(
      /^\| (OGVCS-\d{3}) \| \[[^\]]+\]\(((?:todo|done)\/([^)]+))\) \| (P[012]) \| (.+) \|$/,
    );
    if (!row) continue;

    const [, id, link, filename, priority, dependencyCell] = row;
    if (!release) addError('ROADMAP.md', `${id} appears outside a release section`);
    if (rows.has(id)) addError('ROADMAP.md', `duplicate portfolio row ${id}`);
    rows.set(id, {
      id,
      link,
      filename,
      priority,
      release,
      order: portfolioOrder,
      dependsOn: expandRoadmapDependencies(dependencyCell, `ROADMAP.md ${id}`),
    });
    portfolioOrder += 1;
  }

  validateLocalLinks(roadmapPath, body);
  return rows;
}

function validateGraph(records) {
  for (const record of records.values()) {
    if (record.dependsOn.includes(record.id)) addError(record.location, 'Depends on contains its own PRD ID');
    if (record.blocks.includes(record.id)) addError(record.location, 'Blocks contains its own PRD ID');
    for (const mentionedId of record.mentions) {
      if (!records.has(mentionedId)) {
        addError(record.location, `references missing PRD ${mentionedId}`);
      }
    }
    for (const dependency of record.dependsOn) {
      const predecessor = records.get(dependency);
      if (!predecessor) {
        addError(record.location, `Depends on references missing ${dependency}`);
      } else {
        if (!predecessor.blocks.includes(record.id)) {
          addError(predecessor.location, `Blocks is missing direct dependent ${record.id}`);
        }
        if (
          record.releaseOrdinal !== undefined
          && predecessor.releaseOrdinal !== undefined
          && predecessor.releaseOrdinal > record.releaseOrdinal
        ) {
          addError(record.location, `depends on later-release ${dependency}`);
        }
        if (record.folder === 'done' && predecessor.folder !== 'done') {
          addError(record.location, `done PRD depends on unfinished ${dependency} in ${predecessor.folder}`);
        }
      }
    }
    for (const blocked of record.blocks) {
      const dependent = records.get(blocked);
      if (!dependent) {
        addError(record.location, `Blocks references missing ${blocked}`);
      } else if (!dependent.dependsOn.includes(record.id)) {
        addError(record.location, `Blocks has ${blocked}, but its Depends on omits ${record.id}`);
      }
    }

    const dependencyClosure = new Set([record.id]);
    const remaining = [...record.dependsOn];
    while (remaining.length > 0) {
      const dependency = remaining.pop();
      if (dependencyClosure.has(dependency)) continue;
      dependencyClosure.add(dependency);
      remaining.push(...(records.get(dependency)?.dependsOn ?? []));
    }
    for (const reference of record.implementationReferences) {
      if (!dependencyClosure.has(reference)) {
        addError(
          record.location,
          `Development plan/acceptance references ${reference}, but it is not in the dependency closure`,
        );
      }
    }
    const allowedContractReferences = new Set([...dependencyClosure, ...record.blocks]);
    for (const reference of record.contractReferences) {
      if (!allowedContractReferences.has(reference)) {
        addError(
          record.location,
          `Requirements/interfaces/verification references ${reference}, but it is neither in the dependency closure nor a direct dependent`,
        );
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(id, trail) {
    if (visiting.has(id)) {
      addError(records.get(id)?.location ?? id, `dependency cycle: ${[...trail, id].join(' -> ')}`);
      return;
    }
    if (visited.has(id)) return;

    visiting.add(id);
    for (const dependency of records.get(id)?.dependsOn ?? []) visit(dependency, [...trail, id]);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of records.keys()) visit(id, []);
}

const { records, requirementCount } = collectPrds();
const roadmapRows = collectRoadmapRows();

const numericIds = [...records.keys()].map((id) => Number(id.slice(6))).sort((left, right) => left - right);
for (let expected = 1; expected <= (numericIds.at(-1) ?? 0); expected += 1) {
  if (!numericIds.includes(expected)) {
    addError('todo/done', `missing PRD ID OGVCS-${String(expected).padStart(3, '0')} in the contiguous portfolio`);
  }
}

for (const supportingDocument of ['README.md', 'TEMPLATE.md', 'done/README.md']) {
  const filePath = path.join(prdRoot, supportingDocument);
  validateLocalLinks(filePath, fs.readFileSync(filePath, 'utf8'));
}
const repositoryReadmePath = path.resolve(prdRoot, '..', 'README.md');
if (!fs.existsSync(repositoryReadmePath)) {
  addError('../README.md', 'missing repository entry-point documentation');
} else {
  validateLocalLinks(repositoryReadmePath, fs.readFileSync(repositoryReadmePath, 'utf8'));
}
const architecturePath = path.resolve(prdRoot, '..', 'architecture.md');
validateLocalLinks(architecturePath, fs.readFileSync(architecturePath, 'utf8'));
const adrRoot = path.resolve(prdRoot, '..', 'adr');
for (const filename of fs.readdirSync(adrRoot).filter((name) => name.endsWith('.md')).sort()) {
  const filePath = path.join(adrRoot, filename);
  validateLocalLinks(filePath, fs.readFileSync(filePath, 'utf8'));
}

for (const record of records.values()) {
  const row = roadmapRows.get(record.id);
  if (!row) {
    addError(record.location, 'missing from ROADMAP.md portfolio');
    continue;
  }

  if (row.link !== `${record.folder}/${record.filename}`) {
    addError(record.location, `roadmap link points to ${row.link}`);
  }
  if (row.priority !== record.metadata.Priority) {
    addError(record.location, `priority ${record.metadata.Priority} differs from roadmap ${row.priority}`);
  }
  if (!record.metadata.Release?.startsWith(`${row.release} —`)) {
    addError(record.location, `release ${record.metadata.Release} differs from roadmap ${row.release}`);
  }
  if (!sameOrderedValues(row.dependsOn, record.dependsOn)) {
    addError(
      record.location,
      `Depends on differs from roadmap: header=[${record.dependsOn}] roadmap=[${row.dependsOn}]`,
    );
  }
}

for (const row of roadmapRows.values()) {
  if (!records.has(row.id)) addError('ROADMAP.md', `${row.id} has no PRD file`);
  for (const dependency of row.dependsOn) {
    const dependencyRow = roadmapRows.get(dependency);
    if (dependencyRow?.release === row.release && dependencyRow.order >= row.order) {
      addError('ROADMAP.md', `${row.id} appears before same-release dependency ${dependency}`);
    }
  }
}

validateGraph(records);

if (errors.length > 0) {
  console.error(`Roadmap validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  const todoCount = [...records.values()].filter((record) => record.folder === 'todo').length;
  const doneCount = records.size - todoCount;
  const dependencyCount = [...records.values()].reduce(
    (total, record) => total + record.dependsOn.length,
    0,
  );
  const releaseCount = new Set([...roadmapRows.values()].map((row) => row.release)).size;
  console.log(
    `Roadmap valid: ${records.size} PRDs (${todoCount} todo, ${doneCount} done), `
      + `${releaseCount} releases, ${dependencyCount} direct dependencies, `
      + `${requirementCount} requirement/acceptance IDs.`,
  );
}
