/**
 * Package manifest and lockfile parsers
 * Zero dependencies - uses native JSON parsing and regex
 */

import { readJsonFile, readTextFile } from './files.js';

/**
 * Parses a package.json file and extracts all dependencies
 *
 * @param {string} filePath - Absolute path to package.json
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array<{name: string, versionSpec: string, type: string, filePath: string}>>}
 */
export async function parsePackageJson(filePath, logger = console) {
  try {
    const packageJson = await readJsonFile(filePath);
    const dependencies = [];

    const dependencyTypes = [
      'dependencies',
      'devDependencies',
      'peerDependencies',
      'optionalDependencies',
      'bundledDependencies',
    ];

    for (const depType of dependencyTypes) {
      const deps = packageJson[depType];

      if (!deps || typeof deps !== 'object') {
        continue;
      }

      for (const [name, versionSpec] of Object.entries(deps)) {
        if (typeof versionSpec !== 'string') {
          logger.warn?.(`Skipping dependency ${name} with non-string version in ${filePath}`) ||
            console.warn(`Skipping dependency ${name} with non-string version in ${filePath}`);
          continue;
        }

        dependencies.push({
          name,
          versionSpec,
          type: depType,
          filePath,
        });
      }
    }

    logger.debug?.(`Parsed ${dependencies.length} dependencies from ${filePath}`) ||
      (logger.verbose && console.log(`Parsed ${dependencies.length} dependencies from ${filePath}`));

    return dependencies;
  } catch (error) {
    logger.error?.(`Failed to parse ${filePath}: ${error.message}`) ||
      console.error(`Failed to parse ${filePath}: ${error.message}`);
    return []; // Gracefully handle malformed files
  }
}

/**
 * Parses an npm package-lock.json file (supports v1, v2, v3 formats)
 *
 * @param {string} filePath - Absolute path to package-lock.json
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array<{name: string, version: string, lockfilePath: string}>>}
 */
export async function parsePackageLock(filePath, logger = console) {
  try {
    const lockfile = await readJsonFile(filePath);
    const resolvedPackages = [];

    // Handle lockfile v2/v3 format (npm 7+)
    if (lockfile.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        if (!pkgPath || pkgPath === '') {
          continue; // Skip root package entry
        }

        if (!pkgInfo.version) {
          continue;
        }

        // Extract package name from path
        // node_modules/@scope/package -> @scope/package
        // node_modules/package -> package
        const name = pkgPath.replace(/^node_modules\//, '');

        resolvedPackages.push({
          name,
          version: pkgInfo.version,
          lockfilePath: filePath,
        });
      }
    }
    // Handle lockfile v1 format (npm 5-6)
    else if (lockfile.dependencies) {
      const extractDeps = (deps) => {
        for (const [name, info] of Object.entries(deps)) {
          if (!info.version) {
            continue;
          }

          resolvedPackages.push({
            name,
            version: info.version,
            lockfilePath: filePath,
          });

          // Recursively process nested dependencies
          if (info.dependencies && typeof info.dependencies === 'object') {
            extractDeps(info.dependencies);
          }
        }
      };

      extractDeps(lockfile.dependencies);
    }

    logger.debug?.(`Parsed ${resolvedPackages.length} resolved packages from ${filePath}`) ||
      (logger.verbose && console.log(`Parsed ${resolvedPackages.length} resolved packages from ${filePath}`));

    return resolvedPackages;
  } catch (error) {
    logger.error?.(`Failed to parse ${filePath}: ${error.message}`) ||
      console.error(`Failed to parse ${filePath}: ${error.message}`);
    return [];
  }
}

/**
 * Parses a yarn.lock file (supports v1 and v2/berry formats)
 *
 * @param {string} filePath - Absolute path to yarn.lock
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array<{name: string, version: string, lockfilePath: string}>>}
 */
export async function parseYarnLock(filePath, logger = console) {
  try {
    const content = await readTextFile(filePath);
    const resolvedPackages = [];

    // Yarn.lock format (both v1 and v2):
    // package-name@^1.0.0:
    //   version "1.0.5"
    //   resolved "https://..."

    const entries = content.split('\n\n');

    for (const entry of entries) {
      if (!entry.trim()) {
        continue;
      }

      const lines = entry.split('\n');
      const header = lines[0];

      if (!header || header.startsWith('#') || header.startsWith('__metadata')) {
        continue;
      }

      // Extract package name from header
      // Examples: "package@^1.0.0:", "@scope/package@^1.0.0:", "package@^1.0.0, package@^1.1.0:"
      const nameMatch = header.match(/^"?([^@"]+(?:@[^@"]+)?)[^"]*"?:/);
      if (!nameMatch) {
        continue;
      }

      const name = nameMatch[1];

      // Extract version
      const versionLine = lines.find((line) => line.trim().startsWith('version'));
      if (!versionLine) {
        continue;
      }

      const versionMatch = versionLine.match(/version\s+"([^"]+)"/);
      if (!versionMatch) {
        continue;
      }

      const version = versionMatch[1];

      resolvedPackages.push({
        name,
        version,
        lockfilePath: filePath,
      });
    }

    logger.debug?.(`Parsed ${resolvedPackages.length} resolved packages from ${filePath}`) ||
      (logger.verbose && console.log(`Parsed ${resolvedPackages.length} resolved packages from ${filePath}`));

    return resolvedPackages;
  } catch (error) {
    logger.error?.(`Failed to parse ${filePath}: ${error.message}`) ||
      console.error(`Failed to parse ${filePath}: ${error.message}`);
    return [];
  }
}

/**
 * Parses all discovered package.json files
 *
 * @param {string[]} files - Array of package.json file paths
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array>} All dependencies from all manifests
 */
export async function parseAllManifests(files, logger = console) {
  const allDependencies = [];

  for (const file of files) {
    const deps = await parsePackageJson(file, logger);
    allDependencies.push(...deps);
  }

  return allDependencies;
}

/**
 * Parses all discovered lockfiles
 *
 * @param {Array<{path: string, type: string}>} lockfiles - Array of lockfile info objects
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Array>} All resolved packages from all lockfiles
 */
export async function parseAllLockfiles(lockfiles, logger = console) {
  const allResolvedPackages = [];

  for (const lockfile of lockfiles) {
    let packages = [];

    switch (lockfile.type) {
      case 'npm':
        packages = await parsePackageLock(lockfile.path, logger);
        break;
      case 'yarn':
        packages = await parseYarnLock(lockfile.path, logger);
        break;
      case 'pnpm':
        logger.warn?.(`pnpm lockfiles not yet supported: ${lockfile.path}`) ||
          console.warn(`pnpm lockfiles not yet supported: ${lockfile.path}`);
        break;
    }

    allResolvedPackages.push(...packages);
  }

  return allResolvedPackages;
}
