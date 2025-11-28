/**
 * Vulnerability matching logic
 * Zero dependencies - uses custom semver utilities
 */

import { equal, satisfies, isExactVersion } from './semver.js';

/**
 * Matches direct dependencies with exact versions against IoC database
 *
 * @param {Array} dependencies - Array of package dependencies
 * @param {Map<string, string>} iocMap - Map of package name to compromised version
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Array<{packageName: string, version: string, severity: string, location: string}>}
 */
export function matchDirectDependencies(dependencies, iocMap, logger = console) {
  const matches = [];

  for (const dep of dependencies) {
    const iocVersion = iocMap.get(dep.name);

    if (!iocVersion) {
      continue; // Package not in IoC database
    }

    // Check if it's an exact version match
    if (isExactVersion(dep.versionSpec)) {
      const cleanedSpec = dep.versionSpec.replace(/^v/, '');

      if (equal(cleanedSpec, iocVersion)) {
        matches.push({
          packageName: dep.name,
          version: iocVersion,
          severity: 'DIRECT',
          location: dep.filePath,
        });

        logger.warn?.(`DIRECT match: ${dep.name}@${iocVersion} in ${dep.filePath}`) ||
          console.warn(`DIRECT match: ${dep.name}@${iocVersion} in ${dep.filePath}`);
      }
    }
  }

  logger.info?.(`Direct dependency matching complete: ${matches.length} matches`) ||
    console.log(`Direct dependency matching complete: ${matches.length} matches`);

  return matches;
}

/**
 * Identifies potential matches where version ranges might include IoC version
 *
 * @param {Array} dependencies - Array of package dependencies
 * @param {Map<string, string>} iocMap - Map of package name to compromised version
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Array<{packageName: string, version: string, severity: string, location: string, declaredSpec: string}>}
 */
export function matchPotentialDependencies(dependencies, iocMap, logger = console) {
  const matches = [];

  for (const dep of dependencies) {
    const iocVersion = iocMap.get(dep.name);

    if (!iocVersion) {
      continue;
    }

    // Skip exact versions (already handled by direct matching)
    if (isExactVersion(dep.versionSpec)) {
      continue;
    }

    try {
      // Check if IoC version satisfies the range
      if (satisfies(iocVersion, dep.versionSpec)) {
        matches.push({
          packageName: dep.name,
          version: iocVersion,
          severity: 'POTENTIAL',
          location: dep.filePath,
          declaredSpec: dep.versionSpec,
        });

        logger.debug?.(`POTENTIAL match: ${dep.name}@${dep.versionSpec} (IoC: ${iocVersion}) in ${dep.filePath}`) ||
          (logger.verbose && console.log(`POTENTIAL match: ${dep.name}@${dep.versionSpec} (IoC: ${iocVersion}) in ${dep.filePath}`));
      }
    } catch (error) {
      logger.debug?.(`Failed to parse version range for ${dep.name}@${dep.versionSpec}: ${error.message}`) ||
        (logger.verbose && console.log(`Failed to parse version range for ${dep.name}@${dep.versionSpec}: ${error.message}`));
    }
  }

  logger.info?.(`Potential match identification complete: ${matches.length} matches`) ||
    console.log(`Potential match identification complete: ${matches.length} matches`);

  return matches;
}

/**
 * Matches resolved packages from lockfiles against IoC database
 *
 * @param {Array} resolvedPackages - Array of resolved packages from lockfiles
 * @param {Map<string, string>} iocMap - Map of package name to compromised version
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Array<{packageName: string, version: string, severity: string, location: string}>}
 */
export function matchTransitiveDependencies(resolvedPackages, iocMap, logger = console) {
  const matches = [];

  for (const pkg of resolvedPackages) {
    const iocVersion = iocMap.get(pkg.name);

    if (!iocVersion) {
      continue;
    }

    if (equal(pkg.version, iocVersion)) {
      matches.push({
        packageName: pkg.name,
        version: pkg.version,
        severity: 'TRANSITIVE',
        location: pkg.lockfilePath,
      });

      logger.warn?.(`TRANSITIVE match: ${pkg.name}@${pkg.version} in ${pkg.lockfilePath}`) ||
        console.warn(`TRANSITIVE match: ${pkg.name}@${pkg.version} in ${pkg.lockfilePath}`);
    }
  }

  logger.info?.(`Transitive dependency matching complete: ${matches.length} matches`) ||
    console.log(`Transitive dependency matching complete: ${matches.length} matches`);

  return matches;
}
