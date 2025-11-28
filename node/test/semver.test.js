/**
 * Tests for semver utilities using Node.js test runner
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse, equal, satisfies, isExactVersion } from '../lib/semver.js';

test('parse() should parse valid semver versions', () => {
  assert.deepEqual(parse('1.2.3'), { major: 1, minor: 2, patch: 3, prerelease: null });
  assert.deepEqual(parse('v1.2.3'), { major: 1, minor: 2, patch: 3, prerelease: null });
  assert.deepEqual(parse('1.2.3-beta.1'), { major: 1, minor: 2, patch: 3, prerelease: 'beta.1' });
});

test('parse() should return null for invalid versions', () => {
  assert.equal(parse('invalid'), null);
  assert.equal(parse(''), null);
  assert.equal(parse(null), null);
});

test('equal() should compare versions correctly', () => {
  assert.equal(equal('1.2.3', '1.2.3'), true);
  assert.equal(equal('v1.2.3', '1.2.3'), true);
  assert.equal(equal('1.2.3', '1.2.4'), false);
  assert.equal(equal('1.2.3', '2.2.3'), false);
});

test('satisfies() should handle exact versions', () => {
  assert.equal(satisfies('1.2.3', '1.2.3'), true);
  assert.equal(satisfies('1.2.3', '1.2.4'), false);
});

test('satisfies() should handle caret ranges', () => {
  assert.equal(satisfies('1.2.3', '^1.0.0'), true);
  assert.equal(satisfies('1.5.0', '^1.0.0'), true);
  assert.equal(satisfies('2.0.0', '^1.0.0'), false);
  assert.equal(satisfies('0.2.3', '^0.2.0'), true);
  assert.equal(satisfies('0.3.0', '^0.2.0'), false);
});

test('satisfies() should handle tilde ranges', () => {
  assert.equal(satisfies('1.2.3', '~1.2.0'), true);
  assert.equal(satisfies('1.2.5', '~1.2.0'), true);
  assert.equal(satisfies('1.3.0', '~1.2.0'), false);
});

test('satisfies() should handle comparison operators', () => {
  assert.equal(satisfies('1.2.3', '>=1.0.0'), true);
  assert.equal(satisfies('0.9.0', '>=1.0.0'), false);
  assert.equal(satisfies('1.2.3', '<=2.0.0'), true);
  assert.equal(satisfies('2.1.0', '<=2.0.0'), false);
  assert.equal(satisfies('1.5.0', '>1.0.0'), true);
  assert.equal(satisfies('1.0.0', '<2.0.0'), true);
});

test('satisfies() should handle wildcards', () => {
  assert.equal(satisfies('1.2.3', '*'), true);
  assert.equal(satisfies('100.200.300', '*'), true);
});

test('isExactVersion() should identify exact versions', () => {
  assert.equal(isExactVersion('1.2.3'), true);
  assert.equal(isExactVersion('v1.2.3'), true);
  assert.equal(isExactVersion('^1.2.3'), false);
  assert.equal(isExactVersion('~1.2.3'), false);
  assert.equal(isExactVersion('>=1.2.3'), false);
  assert.equal(isExactVersion('*'), false);
});
