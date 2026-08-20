import { readFileSync } from 'node:fs';

const authority = JSON.parse(readFileSync(
  new URL('../unicode/age-15.0.0-intervals.json', import.meta.url),
  'utf8'
));
if (authority?.schema !== 'ogvcs.repository-format.v1.unicode-age-intervals.v1' ||
    authority.unicodeVersion !== '15.0.0' || authority.intervalCount !== 715 ||
    authority.scalarCount !== 286_785 ||
    authority.sourceSha256 !== '7570877e0fa197c45338f7c41a02636da4e14c8dba6a3611a01cd30bf329d5ca' ||
    authority.repertoire !==
      'Unicode scalar values whose Age is assigned in Unicode 15.0.0; surrogates excluded' ||
    !Array.isArray(authority.intervals) || authority.intervals.length !== 715) {
  throw new Error('invalid packaged Unicode 15.0 authority');
}
let scalarCount = 0;
const intervals = Object.freeze(authority.intervals.map((interval, index) => {
  if (!Array.isArray(interval) || interval.length !== 2 ||
      !Number.isSafeInteger(interval[0]) || !Number.isSafeInteger(interval[1]) ||
      interval[0] < 0 || interval[0] > interval[1] || interval[1] > 0x10ffff ||
      (index > 0 && authority.intervals[index - 1][1] >= interval[0]) ||
      (interval[0] <= 0xdfff && interval[1] >= 0xd800)) {
    throw new Error('invalid packaged Unicode 15.0 interval');
  }
  scalarCount += interval[1] - interval[0] + 1;
  return Object.freeze([interval[0], interval[1]]);
}));
if (scalarCount !== authority.scalarCount) throw new Error('invalid packaged Unicode 15.0 scalar count');

function assigned(codePoint) {
  let low = 0;
  let high = intervals.length - 1;
  while (low <= high) {
    const middle = (low + high) >>> 1;
    const [start, end] = intervals[middle];
    if (codePoint < start) high = middle - 1;
    else if (codePoint > end) low = middle + 1;
    else return true;
  }
  return false;
}

/** Allocation-free frozen Unicode 15.0 scalar-repertoire check. */
export function isUnicode15String(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    let codePoint = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const second = value.charCodeAt(index + 1);
      if (second < 0xdc00 || second > 0xdfff) return false;
      codePoint = 0x10000 + ((first - 0xd800) << 10) + second - 0xdc00;
      index += 1;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    }
    if (!assigned(codePoint)) return false;
  }
  return true;
}
