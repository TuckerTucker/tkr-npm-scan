/**
 * IoC (Indicator of Compromise) database fetcher and parser
 * Zero dependencies - uses native fetch API
 */

const DEFAULT_IOC_URL =
  'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';

/**
 * Fetches and parses the IoC CSV from GitHub
 *
 * @param {string} [url] - Custom CSV URL (optional)
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Promise<Map<string, string>>} Map of package name to compromised version
 */
export async function fetchIoCDatabase(url = DEFAULT_IOC_URL, logger = console) {
  logger.info?.(`Fetching IoC database from ${url}`) || console.log(`Fetching IoC database from ${url}`);

  try {
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const csvText = await response.text();
    const iocMap = parseIoCCsv(csvText, logger);

    logger.info?.(`IoC database loaded: ${iocMap.size} packages`) ||
      console.log(`IoC database loaded: ${iocMap.size} packages`);

    return iocMap;
  } catch (error) {
    logger.error?.(`Failed to fetch IoC database: ${error.message}`) ||
      console.error(`Failed to fetch IoC database: ${error.message}`);
    throw error;
  }
}

/**
 * Parses CSV text into a Map of package name to version
 *
 * CSV format:
 * Package,Version
 * 02-echo,= 0.0.7
 * @accordproject/concerto-analysis,= 3.24.1
 *
 * @param {string} csvText - Raw CSV content
 * @param {object} [logger] - Logger instance (optional)
 * @returns {Map<string, string>} Map of package name to version
 */
export function parseIoCCsv(csvText, logger = console) {
  const iocMap = new Map();
  const lines = csvText.split('\n');

  // Skip header row (line 0)
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();

    if (!line) {
      continue; // Skip empty lines
    }

    const [packageName, versionSpec] = line.split(',');

    if (!packageName || !versionSpec) {
      logger.warn?.(`Skipping malformed CSV line ${i + 1}: ${line}`) ||
        console.warn(`Skipping malformed CSV line ${i + 1}: ${line}`);
      continue;
    }

    // Strip "= " prefix from version (format: "= 0.0.7" -> "0.0.7")
    const version = versionSpec.trim().replace(/^=\s*/, '');

    iocMap.set(packageName.trim(), version);
  }

  logger.debug?.(`Parsed ${iocMap.size} IoC entries`) ||
    (logger.verbose && console.log(`Parsed ${iocMap.size} IoC entries`));

  return iocMap;
}
