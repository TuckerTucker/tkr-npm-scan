/**
 * File system utilities for discovering package files
 * Zero dependencies - uses native fs.promises API
 */

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Recursively finds files matching a pattern
 *
 * @param {string} dir - Directory to search
 * @param {string} filename - Filename to match (e.g., 'package.json')
 * @param {string[]} [exclude] - Directory names to exclude (default: ['node_modules'])
 * @returns {Promise<string[]>} Array of absolute file paths
 */
export async function findFiles(dir, filename, exclude = ['node_modules']) {
  const results = [];

  async function walk(currentPath) {
    try {
      const entries = await readdir(currentPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(currentPath, entry.name);

        // Skip excluded directories
        if (entry.isDirectory() && exclude.includes(entry.name)) {
          continue;
        }

        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.name === filename) {
          results.push(fullPath);
        }
      }
    } catch (error) {
      // Silently skip directories we can't read (permissions, etc.)
      if (error.code !== 'EACCES' && error.code !== 'EPERM') {
        throw error;
      }
    }
  }

  await walk(dir);
  return results;
}

/**
 * Discovers all package.json files in a directory tree
 *
 * @param {string} searchPath - Root directory to search
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<string[]>} Array of absolute paths to package.json files
 */
export async function discoverPackageJsonFiles(searchPath, logger = console) {
  logger.debug?.(`Discovering package.json files in ${searchPath}`) ||
    (logger.verbose && console.log(`Discovering package.json files in ${searchPath}`));

  const files = await findFiles(searchPath, 'package.json');

  logger.info?.(`Discovered ${files.length} package.json files`) ||
    console.log(`Discovered ${files.length} package.json files`);

  return files;
}

/**
 * Discovers all lockfiles in a directory tree
 *
 * @param {string} searchPath - Root directory to search
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array<{path: string, type: string}>>} Array of lockfile info objects
 */
export async function discoverLockfiles(searchPath, logger = console) {
  logger.debug?.(`Discovering lockfiles in ${searchPath}`) ||
    (logger.verbose && console.log(`Discovering lockfiles in ${searchPath}`));

  const lockfileTypes = [
    { filename: 'package-lock.json', type: 'npm' },
    { filename: 'yarn.lock', type: 'yarn' },
    { filename: 'pnpm-lock.yaml', type: 'pnpm' },
  ];

  const lockfiles = [];

  for (const { filename, type } of lockfileTypes) {
    const files = await findFiles(searchPath, filename);
    for (const path of files) {
      lockfiles.push({ path, type });
    }
  }

  logger.info?.(`Discovered ${lockfiles.length} lockfiles`) ||
    console.log(`Discovered ${lockfiles.length} lockfiles`);

  return lockfiles;
}

/**
 * Reads and parses a JSON file
 *
 * @param {string} filePath - Absolute path to JSON file
 * @returns {Promise<object>} Parsed JSON object
 */
export async function readJsonFile(filePath) {
  const content = await readFile(filePath, 'utf-8');
  return JSON.parse(content);
}

/**
 * Reads a text file
 *
 * @param {string} filePath - Absolute path to file
 * @returns {Promise<string>} File contents
 */
export async function readTextFile(filePath) {
  return await readFile(filePath, 'utf-8');
}
