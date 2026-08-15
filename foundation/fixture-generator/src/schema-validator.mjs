import { readFileSync } from 'node:fs';

import { canonicalStringify } from './canonical.mjs';

const SCHEMA_FILES = Object.freeze({
  FixtureManifest: '../schemas/FixtureManifest.schema.json',
  FixtureRequest: '../schemas/FixtureRequest.schema.json',
  GenerationCheckpoint: '../schemas/GenerationCheckpoint.schema.json',
  GroupRelationships: '../schemas/GroupRelationships.schema.json',
  InventoryRecord: '../schemas/InventoryRecord.schema.json',
  LargeFileDescriptor: '../schemas/LargeFileDescriptor.schema.json',
  OperationScenario: '../schemas/OperationScenario.schema.json',
  VerificationResult: '../schemas/VerificationResult.schema.json',
  WorkloadProfile: '../schemas/WorkloadProfile.schema.json',
});

const SCHEMAS = new Map(
  Object.entries(SCHEMA_FILES).map(([name, relative]) => [
    name,
    JSON.parse(readFileSync(new URL(relative, import.meta.url), 'utf8')),
  ]),
);

const SCHEMA_NAMES_BY_ID = new Map(
  [...SCHEMAS.entries()].map(([name, schema]) => [schema.$id, name]),
);

export class SchemaValidationError extends Error {
  constructor(schemaName, issues) {
    const first = issues[0];
    super(`${schemaName} schema validation failed at ${first?.path ?? '$'}: ${first?.message ?? 'invalid document'}`);
    this.name = 'SchemaValidationError';
    this.schemaName = schemaName;
    this.issues = issues;
  }
}

function valueType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isSafeInteger(value)) return 'integer';
  if (typeof value === 'number') return 'number';
  return typeof value;
}

function typeMatches(expected, value) {
  if (expected === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (expected === 'array') return Array.isArray(value);
  if (expected === 'integer') return Number.isSafeInteger(value);
  if (expected === 'number') return typeof value === 'number' && Number.isFinite(value);
  if (expected === 'null') return value === null;
  return typeof value === expected;
}

function equal(left, right) {
  if (
    (left === null || typeof left !== 'object')
    && (right === null || typeof right !== 'object')
  ) return left === right;
  try {
    return canonicalStringify(left) === canonicalStringify(right);
  } catch {
    return Object.is(left, right);
  }
}

function pointerValue(document, pointer) {
  if (pointer === '' || pointer === '#') return document;
  if (!pointer.startsWith('#/')) throw new Error(`Unsupported schema pointer ${pointer}`);
  return pointer.slice(2).split('/').reduce((value, encoded) => {
    const key = encoded.replaceAll('~1', '/').replaceAll('~0', '~');
    if (value === undefined || value === null || !Object.hasOwn(value, key)) {
      throw new Error(`Schema pointer ${pointer} does not exist`);
    }
    return value[key];
  }, document);
}

function resolveReference(reference, context) {
  if (typeof context.document.$id !== 'string') {
    throw new Error(`Schema ${context.schemaName} has no base $id`);
  }
  const resolved = new URL(reference, context.document.$id);
  const fragment = resolved.hash;
  resolved.hash = '';
  const schemaName = SCHEMA_NAMES_BY_ID.get(resolved.href);
  if (!schemaName) throw new Error(`Unsupported schema reference ${reference}`);
  const document = SCHEMAS.get(schemaName);
  return {
    document,
    schema: pointerValue(document, fragment === '' ? '#' : fragment),
    schemaName,
  };
}

function childPath(parent, key) {
  if (typeof key === 'number') return `${parent}[${key}]`;
  return `${parent}.${String(key).replaceAll('~', '~0').replaceAll('.', '\\.')}`;
}

function addIssue(issues, path, keyword, message) {
  issues.push({ keyword, message, path });
}

const WINDOWS_DEVICE_BASENAME = /^(?:aux|clock\$|com[1-9¹²³]|con|conin\$|conout\$|lpt[1-9¹²³]|nul|prn)(?:\.|$)/iu;
const WINDOWS_FORBIDDEN_CHARACTER = /[<>:"\\|?*]/u;

export function containsUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function portableRelativePathIssue(value) {
  if (typeof value !== 'string') return 'must be a string';
  if (value.length === 0) return 'must not be empty';
  if (value.length > 4096) return 'must not exceed 4096 UTF-16 code units';
  if (value.startsWith('/') || /^[A-Za-z]:/u.test(value)) return 'must be relative';
  if (containsUnpairedSurrogate(value)) return 'must not contain an unpaired Unicode surrogate';
  if (Buffer.byteLength(value, 'utf8') > 4096) return 'must not exceed 4096 UTF-8 bytes';
  if (value.normalize('NFC') !== value) return 'must be normalized as NFC';

  const segments = value.split('/');
  for (const segment of segments) {
    if (segment === '') return 'must not contain an empty path segment';
    if (segment === '.' || segment === '..') return 'must not contain a dot or traversal segment';
    if (segment.length > 255) return 'must not contain a segment longer than 255 UTF-16 code units';
    if (Buffer.byteLength(segment, 'utf8') > 255) {
      return 'must not contain a segment longer than 255 UTF-8 bytes';
    }
    if (/\p{Cc}/u.test(segment)) return 'must not contain control characters';
    if (WINDOWS_FORBIDDEN_CHARACTER.test(segment)) {
      return 'must not contain Windows-forbidden characters or alternate-data-stream separators';
    }
    if (/[. ]$/u.test(segment)) return 'must not contain a segment ending in a dot or space';
    if (WINDOWS_DEVICE_BASENAME.test(segment)) return 'must not contain a reserved Windows device name';
  }
  return null;
}

export function isPortableRelativePath(value) {
  return portableRelativePathIssue(value) === null;
}

function validateNode(schema, value, context, path, issues) {
  if (schema === true) return;
  if (schema === false) {
    addIssue(issues, path, 'falseSchema', 'value is forbidden');
    return;
  }
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new TypeError(`Invalid schema node while validating ${context.schemaName}`);
  }

  if (schema.$ref !== undefined) {
    const resolved = resolveReference(schema.$ref, context);
    validateNode(resolved.schema, value, resolved, path, issues);
  }

  if (schema.const !== undefined && !equal(value, schema.const)) {
    addIssue(issues, path, 'const', 'value does not equal the required constant');
  }
  if (schema.enum !== undefined && !schema.enum.some((candidate) => equal(value, candidate))) {
    addIssue(issues, path, 'enum', 'value is not in the supported enumeration');
  }

  if (schema.type !== undefined) {
    const expected = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!expected.some((type) => typeMatches(type, value))) {
      addIssue(
        issues,
        path,
        'type',
        `expected ${expected.join(' or ')}, received ${valueType(value)}`,
      );
      return;
    }
  }

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) {
      addIssue(issues, path, 'minLength', `string is shorter than ${schema.minLength} characters`);
    }
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) {
      addIssue(issues, path, 'maxLength', `string is longer than ${schema.maxLength} characters`);
    }
    if (schema.pattern !== undefined && !(new RegExp(schema.pattern, 'u')).test(value)) {
      addIssue(issues, path, 'pattern', 'string does not match the required pattern');
    }
    if (schema['x-ogvcs-normalization'] !== undefined) {
      const normalization = schema['x-ogvcs-normalization'];
      if (containsUnpairedSurrogate(value)) {
        addIssue(
          issues,
          path,
          'x-ogvcs-normalization',
          'string contains an unpaired Unicode surrogate',
        );
      } else if (value.normalize(normalization) !== value) {
        addIssue(issues, path, 'x-ogvcs-normalization', `string is not normalized as ${normalization}`);
      }
    }
    if (schema['x-ogvcs-portable-relative-path'] === true) {
      const portableIssue = portableRelativePathIssue(value);
      if (portableIssue !== null) {
        addIssue(issues, path, 'x-ogvcs-portable-relative-path', portableIssue);
      }
    }
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) {
      addIssue(issues, path, 'minimum', `number is less than ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      addIssue(issues, path, 'maximum', `number is greater than ${schema.maximum}`);
    }
  }

  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      addIssue(issues, path, 'minItems', `array has fewer than ${schema.minItems} items`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      addIssue(issues, path, 'maxItems', `array has more than ${schema.maxItems} items`);
    }
    if (schema.uniqueItems === true) {
      const seen = new Set();
      for (const item of value) {
        const identity = canonicalStringify(item);
        if (seen.has(identity)) {
          addIssue(issues, path, 'uniqueItems', 'array contains duplicate items');
          break;
        }
        seen.add(identity);
      }
    }
    if (schema.items !== undefined) {
      value.forEach((item, index) => validateNode(
        schema.items,
        item,
        context,
        childPath(path, index),
        issues,
      ));
    }
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) {
      addIssue(issues, path, 'minProperties', `object has fewer than ${schema.minProperties} properties`);
    }
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) {
      addIssue(issues, path, 'maxProperties', `object has more than ${schema.maxProperties} properties`);
    }
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) {
        addIssue(issues, childPath(path, required), 'required', 'required property is missing');
      }
    }
    for (const [key, propertyValue] of Object.entries(value)) {
      if (schema.propertyNames !== undefined) {
        validateNode(schema.propertyNames, key, context, childPath(path, key), issues);
      }
      if (schema.properties?.[key] !== undefined) {
        validateNode(schema.properties[key], propertyValue, context, childPath(path, key), issues);
      } else if (schema.additionalProperties === false) {
        addIssue(issues, childPath(path, key), 'additionalProperties', 'property is not supported');
      } else if (
        schema.additionalProperties !== undefined
        && schema.additionalProperties !== true
        && typeof schema.additionalProperties === 'object'
      ) {
        validateNode(schema.additionalProperties, propertyValue, context, childPath(path, key), issues);
      }
    }
  }

  for (const subSchema of schema.allOf ?? []) {
    validateNode(subSchema, value, context, path, issues);
  }
  if (schema.oneOf !== undefined) {
    let matches = 0;
    for (const subSchema of schema.oneOf) {
      const branchIssues = [];
      validateNode(subSchema, value, context, path, branchIssues);
      if (branchIssues.length === 0) matches += 1;
    }
    if (matches !== 1) {
      addIssue(issues, path, 'oneOf', `value matches ${matches} branches; exactly one is required`);
    }
  }
  if (schema.if !== undefined) {
    const conditionalIssues = [];
    validateNode(schema.if, value, context, path, conditionalIssues);
    if (conditionalIssues.length === 0 && schema.then !== undefined) {
      validateNode(schema.then, value, context, path, issues);
    } else if (conditionalIssues.length > 0 && schema.else !== undefined) {
      validateNode(schema.else, value, context, path, issues);
    }
  }
}

function schemaByName(schemaName) {
  const document = SCHEMAS.get(schemaName);
  if (!document) throw new RangeError(`Unknown fixture schema ${schemaName}`);
  return document;
}

export function validateSchemaDocument(schemaName, value) {
  const document = schemaByName(schemaName);
  const issues = [];
  validateNode(document, value, { document, schemaName }, '$', issues);
  return issues;
}

export function assertSchemaDocument(schemaName, value) {
  const issues = validateSchemaDocument(schemaName, value);
  if (issues.length > 0) throw new SchemaValidationError(schemaName, issues);
  return value;
}

export function validateSchemaFragment(schemaName, pointer, value) {
  const document = schemaByName(schemaName);
  const schema = pointerValue(document, pointer);
  const issues = [];
  validateNode(schema, value, { document, schemaName }, '$', issues);
  return issues;
}

export function assertSchemaFragment(schemaName, pointer, value) {
  const issues = validateSchemaFragment(schemaName, pointer, value);
  if (issues.length > 0) throw new SchemaValidationError(`${schemaName}${pointer}`, issues);
  return value;
}
