/**
 * Output formatters for scan results
 * Zero dependencies - uses ANSI escape codes and native JSON
 */

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
};

/**
 * Formats scan results as human-readable text with colors
 *
 * @param {object} results - Scan results
 * @returns {string} Formatted output string
 */
export function formatHumanReadable(results) {
  const lines = [];

  // Header
  lines.push('');
  lines.push(`${colors.bold}╔════════════════════════════════════════════════════════╗${colors.reset}`);
  lines.push(`${colors.bold}║  NPM VULNERABILITY SCAN RESULTS (shai-hulud)           ║${colors.reset}`);
  lines.push(`${colors.bold}╚════════════════════════════════════════════════════════╝${colors.reset}`);
  lines.push('');

  // Summary
  lines.push(`${colors.bold}SCAN SUMMARY${colors.reset}`);
  lines.push(`${colors.gray}────────────────────────────────────────────────────────${colors.reset}`);
  lines.push(`IoC Database:      ${results.iocCount} packages`);
  lines.push(`Manifests Scanned: ${results.manifestsScanned} files`);
  lines.push(`Lockfiles Scanned: ${results.lockfilesScanned} files`);
  lines.push(`Packages Checked:  ${results.packagesChecked}`);
  lines.push(`Timestamp:         ${results.timestamp}`);
  lines.push('');

  // Results
  const directMatches = results.matches.filter((m) => m.severity === 'DIRECT');
  const transitiveMatches = results.matches.filter((m) => m.severity === 'TRANSITIVE');
  const potentialMatches = results.matches.filter((m) => m.severity === 'POTENTIAL');

  if (results.matches.length === 0) {
    lines.push(`${colors.green}${colors.bold}✓ NO VULNERABILITIES FOUND${colors.reset}`);
    lines.push('');
    lines.push(`${colors.green}All packages appear safe.${colors.reset}`);
  } else {
    lines.push(`${colors.red}${colors.bold}⚠ AFFECTED PACKAGES FOUND: ${results.matches.length}${colors.reset}`);
    lines.push('');

    // Direct matches
    if (directMatches.length > 0) {
      lines.push(`${colors.red}${colors.bold}DIRECT DEPENDENCIES (${directMatches.length})${colors.reset}`);
      lines.push(`${colors.gray}────────────────────────────────────────────────────────${colors.reset}`);

      for (let i = 0; i < directMatches.length; i++) {
        const match = directMatches[i];
        lines.push('');
        lines.push(`${colors.red}${i + 1}. ${match.packageName}@${match.version}${colors.reset}`);
        lines.push(`   ${colors.gray}Location:${colors.reset} ${match.location}`);
        lines.push(`   ${colors.red}Status:${colors.reset} Exact version pin matches IoC`);
        lines.push(`   ${colors.yellow}Action:${colors.reset} Remove or update to a safe version immediately`);
      }

      lines.push('');
    }

    // Transitive matches
    if (transitiveMatches.length > 0) {
      lines.push(`${colors.red}${colors.bold}TRANSITIVE DEPENDENCIES (${transitiveMatches.length})${colors.reset}`);
      lines.push(`${colors.gray}────────────────────────────────────────────────────────${colors.reset}`);

      for (let i = 0; i < transitiveMatches.length; i++) {
        const match = transitiveMatches[i];
        lines.push('');
        lines.push(`${colors.red}${i + 1}. ${match.packageName}@${match.version}${colors.reset}`);
        lines.push(`   ${colors.gray}Resolved:${colors.reset} ${match.location}`);
        lines.push(`   ${colors.yellow}Action:${colors.reset} Update parent packages to versions that don't depend on this package`);
      }

      lines.push('');
    }

    // Potential matches
    if (potentialMatches.length > 0) {
      lines.push(`${colors.yellow}${colors.bold}POTENTIAL MATCHES (${potentialMatches.length})${colors.reset}`);
      lines.push(`${colors.gray}────────────────────────────────────────────────────────${colors.reset}`);

      for (let i = 0; i < potentialMatches.length; i++) {
        const match = potentialMatches[i];
        lines.push('');
        lines.push(`${colors.yellow}${i + 1}. ${match.packageName}${colors.reset}`);
        lines.push(`   ${colors.gray}Declared:${colors.reset} ${match.location} (${match.declaredSpec})`);
        lines.push(`   ${colors.gray}IoC Version:${colors.reset} ${match.version}`);
        lines.push(`   ${colors.yellow}Status:${colors.reset} Range could resolve to affected version`);
        lines.push(`   ${colors.yellow}Action:${colors.reset} Check lockfile to verify resolved version, update if affected`);
      }

      lines.push('');
    }
  }

  lines.push('');

  return lines.join('\n');
}

/**
 * Formats scan results as JSON
 *
 * @param {object} results - Scan results
 * @returns {string} JSON string
 */
export function formatJson(results) {
  return JSON.stringify(results, null, 2);
}
