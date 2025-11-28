/**
 * Minimal semver parser and comparator (zero dependencies)
 * Supports the subset of semver needed for vulnerability scanning
 */

/**
 * Parses a semver version string into components
 *
 * @param {string} version - Version string (e.g., "1.2.3", "v1.2.3")
 * @returns {{major: number, minor: number, patch: number, prerelease: string|null} | null}
 */
export function parse(version) {
  if (!version || typeof version !== 'string') {
    return null;
  }

  // Remove leading 'v'
  const cleaned = version.replace(/^v/, '');

  // Match semver pattern: major.minor.patch[-prerelease]
  const match = cleaned.match(/^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?/);

  if (!match) {
    return null;
  }

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4] || null,
  };
}

/**
 * Compares two semver version objects
 *
 * @param {object} a - Parsed version A
 * @param {object} b - Parsed version B
 * @returns {number} - Returns -1 if a < b, 0 if a === b, 1 if a > b
 */
export function compare(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // Handle prerelease: stable > prerelease
  if (a.prerelease && !b.prerelease) return -1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && b.prerelease) {
    return a.prerelease.localeCompare(b.prerelease);
  }

  return 0;
}

/**
 * Checks if two versions are equal
 *
 * @param {string} a - Version string A
 * @param {string} b - Version string B
 * @returns {boolean}
 */
export function equal(a, b) {
  const parsedA = parse(a);
  const parsedB = parse(b);

  if (!parsedA || !parsedB) return false;

  return compare(parsedA, parsedB) === 0;
}

/**
 * Checks if version satisfies a semver range
 * Supports: ^, ~, >=, <=, >, <, =, exact versions
 *
 * @param {string} version - Version to check (e.g., "1.2.3")
 * @param {string} range - Range specifier (e.g., "^1.0.0", "~1.2.0", ">=1.0.0")
 * @returns {boolean}
 */
export function satisfies(version, range) {
  if (!version || !range) return false;

  const v = parse(version);
  if (!v) return false;

  // Exact version match
  if (!range.match(/[~^><=*x]/)) {
    const r = parse(range);
    return r ? compare(v, r) === 0 : false;
  }

  // Caret range: ^1.2.3 := >=1.2.3 <2.0.0
  if (range.startsWith('^')) {
    const r = parse(range.slice(1));
    if (!r) return false;

    if (v.major !== r.major) return false;
    if (r.major === 0) {
      // ^0.x.y is special: locks minor version
      if (v.minor !== r.minor) return false;
      if (r.minor === 0) {
        // ^0.0.x locks patch too
        return v.patch >= r.patch;
      }
      return compare(v, r) >= 0;
    }
    return compare(v, r) >= 0;
  }

  // Tilde range: ~1.2.3 := >=1.2.3 <1.3.0
  if (range.startsWith('~')) {
    const r = parse(range.slice(1));
    if (!r) return false;

    if (v.major !== r.major || v.minor !== r.minor) return false;
    return v.patch >= r.patch;
  }

  // Comparison operators
  if (range.startsWith('>=')) {
    const r = parse(range.slice(2));
    return r ? compare(v, r) >= 0 : false;
  }

  if (range.startsWith('<=')) {
    const r = parse(range.slice(2));
    return r ? compare(v, r) <= 0 : false;
  }

  if (range.startsWith('>')) {
    const r = parse(range.slice(1));
    return r ? compare(v, r) > 0 : false;
  }

  if (range.startsWith('<')) {
    const r = parse(range.slice(1));
    return r ? compare(v, r) < 0 : false;
  }

  if (range.startsWith('=')) {
    const r = parse(range.slice(1));
    return r ? compare(v, r) === 0 : false;
  }

  // Wildcard: * or x
  if (range === '*' || range === 'x') {
    return true;
  }

  // 1.x or 1.* := >=1.0.0 <2.0.0
  const wildcardMatch = range.match(/^(\d+)\.([x*]|(\d+)\.[x*])$/);
  if (wildcardMatch) {
    const major = parseInt(wildcardMatch[1], 10);
    if (v.major !== major) return false;

    if (wildcardMatch[2] === 'x' || wildcardMatch[2] === '*') {
      return true; // 1.x matches any 1.y.z
    }

    const minor = parseInt(wildcardMatch[3], 10);
    return v.minor === minor; // 1.2.x matches any 1.2.z
  }

  // Unknown range format
  return false;
}

/**
 * Checks if version string is an exact version (no range operators)
 *
 * @param {string} versionSpec - Version specifier
 * @returns {boolean}
 */
export function isExactVersion(versionSpec) {
  if (!versionSpec) return false;

  // Check for range operators
  const hasRangeOperator = /[~^><=*x]/.test(versionSpec);
  if (hasRangeOperator) return false;

  // Verify it's a valid semver
  return parse(versionSpec) !== null;
}
