import assert from 'node:assert/strict';

export function assertVectorOutcome(id, actual, expected) {
  assert.equal(actual, expected, `${id} returned an unexpected outcome`);
  if (process.env.OGVCS_VECTOR_CASE === id) {
    process.stdout.write(`OGVCS_VECTOR_RESULT ${id} ${JSON.stringify(actual)}\n`);
  }
  return actual;
}

export async function assertVectorRejection(id, operation, expected) {
  let rejected;
  try { await operation(); }
  catch (error) { rejected = error; }
  assert.notEqual(rejected, undefined, `${id} unexpectedly succeeded`);
  return assertVectorOutcome(id, rejected?.code, expected);
}

export function assertVectorThrow(id, operation, expected) {
  let thrown;
  try { operation(); }
  catch (error) { thrown = error; }
  assert.notEqual(thrown, undefined, `${id} unexpectedly succeeded`);
  return assertVectorOutcome(id, thrown?.code, expected);
}
