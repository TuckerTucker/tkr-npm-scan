# tkr-npm-scan

**Zero-Dependency** NPM vulnerability scanner for detecting packages affected by the **shai-hulud** supply chain attack.

**Zero-dependency approach:**
- Uses ONLY Node.js built-in modules

## Overview

This CLI tool scans npm projects to identify packages compromised in the shai-hulud supply chain attack by cross-referencing your dependencies against the known Indicators of Compromise (IoC) published by Wiz Security Research.

**Features:**

- ✅ **Zero external dependencies** - Only Node.js built-ins
- ✅ **Direct dependency detection** - Finds exact version matches in `package.json`
- ✅ **Transitive dependency detection** - Scans lockfiles for compromised packages deep in the dependency tree
- ✅ **Multi-lockfile support** - Works with npm and Yarn
- ✅ **Monorepo-aware** - Discovers all `package.json` files recursively
- ✅ **Version range analysis** - Identifies potential matches where ranges might resolve to vulnerable versions
- ✅ **Actionable output** - Provides remediation guidance for each finding

## Installation

### Clone and run

```bash
git clone https://github.com/tuckertucker/tkr-npm-scan.git
cd tkr-npm-scan
git checkout no-npm
node cli.js /path/to/scan
```

## Usage

### Options

```
USAGE:
  node cli.js [path] [options]

OPTIONS:
  -p, --path <dir>          Target directory to scan
  -j, --json                Output results as JSON
  -v, --verbose             Enable verbose logging
  --csv-url <url>           Custom IoC CSV URL
  --lockfile-only           Only scan lockfiles, skip package.json
  -h, --help                Show help message
```

### Examples

**Scan with verbose logging:**
```bash
node cli.js --verbose
```

**JSON output for CI/CD:**
```bash
node cli.js --json > scan-results.json
```

**Only check resolved dependencies:**
```bash
node cli.js --lockfile-only
```

**Scan multiple projects:**
```bash
node cli.js /path/to/project1 && node cli.js /path/to/project2
```

## Output

### Human-Readable Format

```
╔════════════════════════════════════════════════════════╗
║  NPM VULNERABILITY SCAN RESULTS (shai-hulud)           ║
╚════════════════════════════════════════════════════════╝

SCAN SUMMARY
────────────────────────────────────────────────────────
IoC Database:      795 packages
Manifests Scanned: 5 files
Lockfiles Scanned: 2 files
Packages Checked:  1923
Timestamp:         2025-11-28T03:50:00.000Z

⚠ AFFECTED PACKAGES FOUND: 2

DIRECT DEPENDENCIES (1)
────────────────────────────────────────────────────────

1. vulnerable-pkg@1.0.0
   Location: ./package.json
   Status: Exact version pin matches IoC
   Action: Remove or update to a safe version immediately

TRANSITIVE DEPENDENCIES (1)
────────────────────────────────────────────────────────

1. @accordproject/concerto-analysis@3.24.1
   Resolved: ./package-lock.json
   Action: Update parent packages to versions that don't depend on this package
```

### JSON Format

```json
{
  "manifestsScanned": 5,
  "lockfilesScanned": 2,
  "packagesChecked": 1923,
  "matches": [
    {
      "packageName": "vulnerable-pkg",
      "version": "1.0.0",
      "severity": "DIRECT",
      "location": "/path/to/package.json"
    }
  ],
  "timestamp": "2025-11-28T03:50:00.000Z",
  "iocCount": 795
}
```

## How It Works

1. **Fetches IoC database** - Downloads the latest CSV of compromised packages (native `fetch`) from [wiz research IoC](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/shai-hulud-2-packages.csv)
2. **Discovers manifests** - Finds all `package.json` files (recursive `readdir`)
3. **Discovers lockfiles** - Locates `package-lock.json`, `yarn.lock`
4. **Parses dependencies** - Extracts both direct and transitive dependencies (native JSON parsing)
5. **Matches against IoCs** - Cross-references package names and versions (custom semver logic)
6. **Reports findings** - Displays results with severity levels and remediation guidance

## Detection Levels

### DIRECT
Exact version match in `package.json` dependencies.

**Example:**
```json
"dependencies": {
  "vulnerable-pkg": "1.0.0"  // ⚠️ Exact match to IoC
}
```

### TRANSITIVE
Resolved package in lockfile that matches IoC exactly.

**Example:**
Your app depends on `lib-a@2.0.0`, which depends on `vulnerable-pkg@1.0.0`.

### POTENTIAL
Version range in `package.json` that could resolve to compromised version.

**Example:**
```json
"dependencies": {
  "vulnerable-pkg": "^1.0.0"  // ⚠️ Range includes 1.0.0
}
```

Verify with lockfile to confirm actual resolved version.


## Testing

Uses Node.js built-in test runner (`node:test`) - no external test frameworks:

```bash
node --test test/*.test.js
```

Sample test output:
```
TAP version 13
ok 1 - parse() should parse valid semver versions
ok 2 - satisfies() should handle caret ranges
# tests 9
# pass 9
```

## Data Source

IoC data sourced from [Wiz Security Research](https://github.com/wiz-sec-public/wiz-research-iocs):
- **Repository:** `wiz-sec-public/wiz-research-iocs`
- **File:** `reports/shai-hulud-2-packages.csv`
- **Format:** `Package,Version` (exact versions only)


## License

MIT

## Acknowledgments

- [Wiz Security Research](https://www.wiz.io/security-research) for the IoC database
- The npm security community for rapid response to supply chain attacks

---

**Stay safe. Scan your dependencies. Trust no one.** 🔒
