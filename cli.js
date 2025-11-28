#!/usr/bin/env node
/**
 * CLI entry point for zero-dependency npm vulnerability scanner
 * No external dependencies - uses only Node.js built-in modules
 */

import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { runScan } from './lib/scanner.js';
import { formatHumanReadable, formatJson } from './lib/formatter.js';

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
  -h, --help                Show this help message

EXAMPLES:
  npm-scan                          Scan current directory
  npm-scan /path/to/project         Scan specific directory
  npm-scan --json                   Output JSON for CI/CD integration
  npm-scan --verbose                Enable debug logging
  npm-scan --lockfile-only          Only check resolved dependencies

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
