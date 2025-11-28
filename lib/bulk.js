/**
 * Bulk scanning utilities for processing multiple paths
 * No external dependencies - uses only Node.js built-in modules
 */

import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, basename } from 'node:path';

/**
 * Reads and parses a bulk paths file
 * @param {string} filePath - Path to file containing newline-separated directory paths
 * @returns {string[]} - Array of resolved absolute paths
 */
export function readPathsFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');

  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#')) // Remove empty lines and comments
    .map(line => resolve(line));
}

/**
 * Sanitizes a path to create a safe directory name
 * Examples:
 *   /path/to/project -> path-to-project
 *   /home/user/app/ -> home-user-app
 * @param {string} fullPath - Full path to sanitize
 * @returns {string} - Sanitized directory name
 */
export function sanitizePathForDirectory(fullPath) {
  return fullPath
    .replace(/^\/+/, '') // Remove leading slashes
    .replace(/\/+$/, '') // Remove trailing slashes
    .replace(/\//g, '-') // Replace slashes with hyphens
    .replace(/[^a-zA-Z0-9-_.]/g, '-') // Replace special chars
    .replace(/-+/g, '-') // Collapse multiple hyphens
    .toLowerCase();
}

/**
 * Creates a timestamp-based directory structure for bulk scan results
 * @param {string} baseDir - Base directory (default: 'results')
 * @returns {string} - Path to created timestamp directory
 */
export function createTimestampedDirectory(baseDir = 'results') {
  const timestamp = new Date()
    .toISOString()
    .replace(/T/, '-')
    .replace(/:/g, '-')
    .replace(/\..+/, ''); // Format: YYYY-MM-DD-HH-mm-ss

  const timestampDir = resolve(baseDir, timestamp);

  // Create base directory if it doesn't exist
  if (!existsSync(baseDir)) {
    mkdirSync(baseDir, { recursive: true });
  }

  // Create timestamp directory
  mkdirSync(timestampDir, { recursive: true });

  return timestampDir;
}

/**
 * Creates a subdirectory for a specific scan path
 * @param {string} parentDir - Parent directory
 * @param {string} scanPath - Original scan path
 * @returns {string} - Path to created subdirectory
 */
export function createScanDirectory(parentDir, scanPath) {
  const dirName = sanitizePathForDirectory(scanPath);
  const scanDir = resolve(parentDir, dirName);

  if (!existsSync(scanDir)) {
    mkdirSync(scanDir, { recursive: true });
  }

  return scanDir;
}

/**
 * Saves scan results to JSON file
 * @param {string} directory - Target directory
 * @param {Object} results - Scan results object
 */
export function saveResultsJson(directory, results) {
  const filePath = resolve(directory, 'results.json');
  writeFileSync(filePath, JSON.stringify(results, null, 2), 'utf-8');
}

/**
 * Saves verbose log output to text file
 * @param {string} directory - Target directory
 * @param {string} logContent - Log content
 */
export function saveVerboseLog(directory, logContent) {
  const filePath = resolve(directory, 'verbose.txt');
  writeFileSync(filePath, logContent, 'utf-8');
}

/**
 * Saves error information to text file
 * @param {string} directory - Target directory
 * @param {Error} error - Error object
 */
export function saveError(directory, error) {
  const filePath = resolve(directory, 'error.txt');
  const content = `Error: ${error.message}\n\nStack:\n${error.stack}`;
  writeFileSync(filePath, content, 'utf-8');
}

/**
 * Generates and saves summary report for bulk scan
 * @param {string} directory - Results directory
 * @param {Array} scanResults - Array of scan result objects
 */
export function saveSummaryReport(directory, scanResults) {
  const summary = {
    totalScanned: scanResults.length,
    vulnerabilitiesFound: scanResults.filter(r => r.status === 'vulnerable').length,
    cleanScans: scanResults.filter(r => r.status === 'clean').length,
    failedScans: scanResults.filter(r => r.status === 'error').length,
    timestamp: new Date().toISOString(),
    paths: scanResults.map(r => ({
      path: r.path,
      status: r.status,
      matches: r.matches || 0,
      error: r.error || null,
    })),
  };

  const filePath = resolve(directory, 'summary.json');
  writeFileSync(filePath, JSON.stringify(summary, null, 2), 'utf-8');

  return summary;
}

/**
 * Creates a logger that captures output to a string buffer
 * @param {boolean} verbose - Enable verbose logging
 * @returns {Object} - Logger with captured output
 */
export function createCapturingLogger(verbose) {
  const buffer = [];

  const logger = {
    info: (msg) => {
      const line = `[INFO] ${msg}`;
      console.log(line);
      buffer.push(line);
    },
    warn: (msg) => {
      const line = `[WARN] ${msg}`;
      console.warn(line);
      buffer.push(line);
    },
    error: (msg) => {
      const line = `[ERROR] ${msg}`;
      console.error(line);
      buffer.push(line);
    },
    debug: (msg) => {
      if (verbose) {
        const line = `[DEBUG] ${msg}`;
        console.log(line);
        buffer.push(line);
      }
    },
    verbose,
    getBuffer: () => buffer.join('\n'),
    clearBuffer: () => { buffer.length = 0; },
  };

  return logger;
}
