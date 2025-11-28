/**
 * Main scanner orchestration
 * Zero dependencies - coordinates all scanning components
 */

import { fetchIoCDatabase } from './ioc.js';
import { discoverPackageJsonFiles, discoverLockfiles } from './files.js';
import { parseAllManifests, parseAllLockfiles } from './parsers.js';
import { matchDirectDependencies, matchPotentialDependencies, matchTransitiveDependencies } from './matcher.js';

/**
 * Runs a complete vulnerability scan
 *
 * @param {object} options - Scan options
 * @param {string} options.path - Target directory to scan
 * @param {string} [options.csvUrl] - Custom IoC CSV URL
 * @param {boolean} [options.lockfileOnly] - Only scan lockfiles, skip package.json
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<object>} Scan results
 */
export async function runScan(options, logger = console) {
  const startTime = Date.now();

  logger.info?.(`Starting vulnerability scan of ${options.path}`) ||
    console.log(`Starting vulnerability scan of ${options.path}`);

  // Step 1: Fetch IoC database
  const iocMap = await fetchIoCDatabase(options.csvUrl, logger);

  // Step 2: Scan manifests (unless lockfile-only mode)
  let manifestDeps = [];
  let manifestFiles = [];

  if (!options.lockfileOnly) {
    manifestFiles = await discoverPackageJsonFiles(options.path, logger);
    manifestDeps = await parseAllManifests(manifestFiles, logger);
  }

  // Step 3: Scan lockfiles
  const lockfiles = await discoverLockfiles(options.path, logger);
  const resolvedPackages = await parseAllLockfiles(lockfiles, logger);

  // Step 4: Match direct dependencies
  const directMatches = options.lockfileOnly
    ? []
    : matchDirectDependencies(manifestDeps, iocMap, logger);

  // Step 5: Identify potential matches (version ranges)
  const potentialMatches = options.lockfileOnly
    ? []
    : matchPotentialDependencies(manifestDeps, iocMap, logger);

  // Step 6: Match resolved packages (transitive)
  const transitiveMatches = matchTransitiveDependencies(resolvedPackages, iocMap, logger);

  // Step 7: Aggregate results
  const allMatches = [...directMatches, ...potentialMatches, ...transitiveMatches];

  const elapsedMs = Date.now() - startTime;

  const results = {
    manifestsScanned: manifestFiles.length,
    lockfilesScanned: lockfiles.length,
    packagesChecked: manifestDeps.length + resolvedPackages.length,
    matches: allMatches,
    timestamp: new Date().toISOString(),
    iocCount: iocMap.size,
    elapsedMs,
  };

  logger.info?.(`Scan complete: ${allMatches.length} matches found in ${elapsedMs}ms`) ||
    console.log(`Scan complete: ${allMatches.length} matches found in ${elapsedMs}ms`);

  return results;
}
