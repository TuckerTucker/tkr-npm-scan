#!/usr/bin/env node
/**
 * CLI entry point for zero-dependency npm vulnerability scanner
 * No external dependencies - uses only Node.js built-in modules
 */

import { parseArgs } from 'node:util';
import { resolve, relative } from 'node:path';
import { existsSync } from 'node:fs';
import { runScan } from './lib/scanner.js';
import { formatHumanReadable, formatJson } from './lib/formatter.js';
import {
  readPathsFile,
  createTimestampedDirectory,
  createScanDirectory,
  saveResultsJson,
  saveVerboseLog,
  saveError,
  saveSummaryReport,
  createCapturingLogger,
} from './lib/bulk.js';

const DEFAULT_CSV_URL =
  'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';

/**
 * Simple logger that respects verbose flag
 */
function createLogger(verbose) {
  return {
    info: (msg) => console.log(`[INFO] ${msg}`),
    warn: (msg) => console.warn(`[WARN] ${msg}`),
    error: (msg) => console.error(`[ERROR] ${msg}`),
    debug: (msg) => verbose && console.log(`[DEBUG] ${msg}`),
    verbose,
  };
}

/**
 * Shows CLI help text
 */
function showHelp() {
  console.log(`
npm-scan - Zero-Dependency NPM Vulnerability Scanner

USAGE:
  npm-scan [path] [options]

ARGUMENTS:
  path                Target directory to scan (default: current directory)

OPTIONS:
  -p, --path <dir>          Target directory to scan
  -j, --json                Output results as JSON
  -v, --verbose             Enable verbose logging
  --csv-url <url>           Custom IoC CSV URL
  --lockfile-only           Only scan lockfiles, skip package.json
  --bulk <file>             Scan multiple paths from file, save to results/ directory
  -h, --help                Show this help message

EXAMPLES:
  npm-scan                          Scan current directory
  npm-scan /path/to/project         Scan specific directory
  npm-scan --json                   Output JSON for CI/CD integration
  npm-scan --verbose                Enable debug logging
  npm-scan --lockfile-only          Only check resolved dependencies
  npm-scan --bulk paths.txt -j -v   Scan multiple paths, save results by timestamp

EXIT CODES:
  0  No vulnerabilities found
  1  Vulnerabilities detected
  2  Scan error

ZERO DEPENDENCIES:
  This scanner uses ONLY Node.js built-in modules (no npm packages).
  This eliminates supply chain attack surface and makes the tool fully auditable.

SECURITY ADVISORY:
  This tool scans for packages affected by the shai-hulud supply chain attack.
  IoC data sourced from: wiz-sec-public/wiz-research-iocs

For more information, visit:
  https://github.com/wiz-sec-public/wiz-research-iocs
`);
}

/**
 * Performs bulk scanning of multiple paths
 * @param {Array} paths - Array of paths to scan
 * @param {Object} values - CLI options
 * @returns {number} - Exit code
 */
async function runBulkScan(paths, values) {
  const timestampDir = createTimestampedDirectory('results');
  console.log(`\nBulk scan started`);
  console.log(`Results will be saved to: ${timestampDir}\n`);

  const scanResults = [];
  let hasVulnerabilities = false;

  for (let i = 0; i < paths.length; i++) {
    const scanPath = paths[i];
    const scanNum = `[${i + 1}/${paths.length}]`;

    console.log(`${scanNum} Scanning ${scanPath} ...`);

    // Check if path exists
    if (!existsSync(scanPath)) {
      console.error(`${scanNum} Error: Path does not exist - ${scanPath}`);
      const scanDir = createScanDirectory(timestampDir, scanPath);
      saveError(scanDir, new Error(`Path does not exist: ${scanPath}`));
      scanResults.push({
        path: scanPath,
        status: 'error',
        error: 'Path does not exist',
      });
      continue;
    }

    // Create directory for this scan
    const scanDir = createScanDirectory(timestampDir, scanPath);

    // Create capturing logger for this scan
    const logger = createCapturingLogger(values.verbose);

    try {
      const options = {
        path: resolve(scanPath),
        csvUrl: values['csv-url'],
        lockfileOnly: values['lockfile-only'],
      };

      // Run the scan
      const results = await runScan(options, logger);

      // Save results.json
      saveResultsJson(scanDir, results);

      // Save verbose.txt if verbose mode enabled
      if (values.verbose) {
        saveVerboseLog(scanDir, logger.getBuffer());
      }

      // Determine status
      const status = results.matches.length > 0 ? 'vulnerable' : 'clean';
      if (status === 'vulnerable') {
        hasVulnerabilities = true;
      }

      scanResults.push({
        path: scanPath,
        status,
        matches: results.matches.length,
      });

      console.log(`${scanNum} Complete - ${status.toUpperCase()} (${results.matches.length} matches)\n`);
    } catch (error) {
      console.error(`${scanNum} Error: ${error.message}\n`);
      saveError(scanDir, error);

      if (values.verbose) {
        saveVerboseLog(scanDir, logger.getBuffer());
      }

      scanResults.push({
        path: scanPath,
        status: 'error',
        error: error.message,
      });
    }
  }

  // Generate summary report
  const summary = saveSummaryReport(timestampDir, scanResults);

  console.log('═'.repeat(60));
  console.log('BULK SCAN SUMMARY');
  console.log('═'.repeat(60));
  console.log(`Total Scanned:     ${summary.totalScanned}`);
  console.log(`Clean:             ${summary.cleanScans}`);
  console.log(`Vulnerable:        ${summary.vulnerabilitiesFound}`);
  console.log(`Failed:            ${summary.failedScans}`);
  console.log(`Results Directory: ${timestampDir}`);
  console.log('═'.repeat(60));

  // Exit with appropriate code
  if (summary.failedScans > 0) {
    return 2; // Scan errors
  } else if (hasVulnerabilities) {
    return 1; // Vulnerabilities found
  } else {
    return 0; // Clean
  }
}

/**
 * Main CLI function
 */
async function main() {
  try {
    // Parse command-line arguments
    const { values, positionals } = parseArgs({
      options: {
        path: {
          type: 'string',
          short: 'p',
          default: process.cwd(),
        },
        json: {
          type: 'boolean',
          short: 'j',
          default: false,
        },
        verbose: {
          type: 'boolean',
          short: 'v',
          default: false,
        },
        'csv-url': {
          type: 'string',
          default: DEFAULT_CSV_URL,
        },
        'lockfile-only': {
          type: 'boolean',
          default: false,
        },
        bulk: {
          type: 'string',
        },
        help: {
          type: 'boolean',
          short: 'h',
          default: false,
        },
      },
      allowPositionals: true,
    });

    // Show help
    if (values.help) {
      showHelp();
      process.exit(0);
    }

    // Handle bulk scanning mode
    if (values.bulk) {
      if (!existsSync(values.bulk)) {
        throw new Error(`Bulk paths file not found: ${values.bulk}`);
      }

      const paths = readPathsFile(values.bulk);

      if (paths.length === 0) {
        throw new Error(`No valid paths found in ${values.bulk}`);
      }

      const exitCode = await runBulkScan(paths, values);
      process.exit(exitCode);
    }

    // Single scan mode (original behavior)
    // Use positional argument as path if provided
    const targetPath = positionals[0] || values.path;

    const options = {
      path: resolve(targetPath),
      csvUrl: values['csv-url'],
      lockfileOnly: values['lockfile-only'],
    };

    const logger = createLogger(values.verbose);

    // Run the scan
    const results = await runScan(options, logger);

    // Format and output results
    if (values.json) {
      console.log(formatJson(results));
    } else {
      console.log(formatHumanReadable(results));
    }

    // Exit with error code if vulnerabilities found
    if (results.matches.length > 0) {
      process.exit(1);
    }

    process.exit(0);
  } catch (error) {
    console.error(`\n${error.message}`);
    if (process.env.DEBUG) {
      console.error(error.stack);
    }
    process.exit(2);
  }
}

// Run CLI
main();
