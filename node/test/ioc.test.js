/**
 * Tests for IoC (Indicator of Compromise) parser
 * Validates CSV parsing with single and multiple versions
 */

import { parseIoCCsv } from '../lib/ioc.js';
import { strict as assert } from 'assert';

// Test single version parsing
function testSingleVersion() {
  const csv = `Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1`;

  const result = parseIoCCsv(csv);

  assert.ok(result instanceof Map, 'Result should be a Map');
  assert.strictEqual(result.size, 2, 'Should have 2 packages');
  assert.deepStrictEqual(result.get('02-echo'), ['0.0.7'], '02-echo should have version 0.0.7');
  assert.deepStrictEqual(
    result.get('@accordproject/concerto-analysis'),
    ['3.24.1'],
    '@accordproject/concerto-analysis should have version 3.24.1'
  );
}

// Test multiple versions with || separator
function testMultipleVersionsWithSeparator() {
  const csv = `Package,Version
@zapier/ai-actions,= 0.1.18 || = 0.1.19 || = 0.1.20`;

  const result = parseIoCCsv(csv);

  assert.ok(result instanceof Map, 'Result should be a Map');
  assert.strictEqual(result.size, 1, 'Should have 1 package');

  const versions = result.get('@zapier/ai-actions');
  assert.ok(Array.isArray(versions), 'Versions should be an array');
  assert.strictEqual(versions.length, 3, 'Should have 3 versions');
  assert.deepStrictEqual(
    versions,
    ['0.1.18', '0.1.19', '0.1.20'],
    'Should parse all three versions correctly'
  );
}

// Test mixed single and multiple versions
function testMixedVersions() {
  const csv = `Package,Version
single-pkg,= 1.0.0
@zapier/ai-actions-react,= 0.1.12 || = 0.1.13 || = 0.1.14
another-single,= 2.0.0`;

  const result = parseIoCCsv(csv);

  assert.strictEqual(result.size, 3, 'Should have 3 packages');
  assert.deepStrictEqual(result.get('single-pkg'), ['1.0.0'], 'single-pkg should have 1 version');
  assert.deepStrictEqual(
    result.get('@zapier/ai-actions-react'),
    ['0.1.12', '0.1.13', '0.1.14'],
    '@zapier/ai-actions-react should have 3 versions'
  );
  assert.deepStrictEqual(result.get('another-single'), ['2.0.0'], 'another-single should have 1 version');
}

// Test with extra whitespace
function testWhitespaceHandling() {
  const csv = `Package,Version
pkg-with-spaces,  =  1.0.0  ||  =  1.0.1  ||  =  1.0.2  `;

  const result = parseIoCCsv(csv);

  assert.strictEqual(result.size, 1, 'Should have 1 package');

  const versions = result.get('pkg-with-spaces');
  assert.deepStrictEqual(
    versions,
    ['1.0.0', '1.0.1', '1.0.2'],
    'Should handle whitespace correctly'
  );
}

// Test empty CSV
function testEmptyCSV() {
  const csv = `Package,Version
`;

  const result = parseIoCCsv(csv);

  assert.strictEqual(result.size, 0, 'Should have 0 packages for empty CSV');
}

// Test with empty lines
function testEmptyLines() {
  const csv = `Package,Version
pkg1,= 1.0.0

pkg2,= 2.0.0

`;

  const result = parseIoCCsv(csv);

  assert.strictEqual(result.size, 2, 'Should have 2 packages (empty lines ignored)');
  assert.deepStrictEqual(result.get('pkg1'), ['1.0.0'], 'pkg1 should be parsed');
  assert.deepStrictEqual(result.get('pkg2'), ['2.0.0'], 'pkg2 should be parsed');
}

// Test multiple CSV rows for same package (legacy format support)
function testMultipleRowsSamePackage() {
  const csv = `Package,Version
vulnerable,= 1.0.0
vulnerable,= 1.0.1`;

  const result = parseIoCCsv(csv);

  assert.strictEqual(result.size, 1, 'Should have 1 package');

  const versions = result.get('vulnerable');
  assert.strictEqual(versions.length, 2, 'Should have 2 versions');
  assert.deepStrictEqual(
    versions,
    ['1.0.0', '1.0.1'],
    'Should accumulate versions from multiple rows'
  );
}

// Run all tests
function runTests() {
  const tests = [
    { name: 'Single version parsing', fn: testSingleVersion },
    { name: 'Multiple versions with || separator', fn: testMultipleVersionsWithSeparator },
    { name: 'Mixed single and multiple versions', fn: testMixedVersions },
    { name: 'Whitespace handling', fn: testWhitespaceHandling },
    { name: 'Empty CSV', fn: testEmptyCSV },
    { name: 'Empty lines', fn: testEmptyLines },
    { name: 'Multiple rows same package', fn: testMultipleRowsSamePackage },
  ];

  let passed = 0;
  let failed = 0;

  console.log('Running IoC parser tests...\n');

  for (const test of tests) {
    try {
      test.fn();
      console.log(`✓ ${test.name}`);
      passed++;
    } catch (error) {
      console.log(`✗ ${test.name}`);
      console.log(`  Error: ${error.message}`);
      failed++;
    }
  }

  console.log(`\nTests: ${passed} passed, ${failed} failed, ${tests.length} total`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
