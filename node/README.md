# tkr-npm-scan (Node.js Implementation)

**Zero-Dependency** NPM vulnerability scanner for detecting packages affected by the **shai-hulud** supply chain attack.

**Zero-dependency approach:**
- Uses ONLY Node.js built-in modules
- No `npm install` required
- Portable and lightweight

## Installation

### Clone and run

```bash
git clone https://github.com/tuckertucker/tkr-npm-scan.git
cd tkr-npm-scan/node
node npm-scan.js /path/to/scan
```

## Usage

### Options

```
USAGE:
  node npm-scan.js [path] [options]

OPTIONS:
  -p, --path <dir>          Target directory to scan
  -j, --json                Output results as JSON
  -v, --verbose             Enable verbose logging
  --csv-url <url>           Custom IoC CSV URL
  --lockfile-only           Only scan lockfiles, skip package.json
  --bulk <file>             Scan multiple paths from file, save to results/ directory
  -h, --help                Show help message
```

### Examples

**Scan current directory:**
```bash
node npm-scan.js
```

**Scan with verbose logging:**
```bash
node npm-scan.js --verbose
```

**JSON output for CI/CD:**
```bash
node npm-scan.js --json > scan-results.json
```

**Only check resolved dependencies:**
```bash
node npm-scan.js --lockfile-only
```

**Bulk scan multiple projects:**
```bash
# Create a file with paths to scan
cat > paths.txt << EOF
/path/to/project1
/path/to/project2
/path/to/project3
EOF

# Run bulk scan with JSON and verbose output
node npm-scan.js --bulk paths.txt -j -v
```

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

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected
- `2` - Error during scan

## Implementation Details

### Built-in Modules Used

- `fs` - File system operations
- `path` - Path manipulation
- `http`/`https` - IoC database fetching
- `url` - URL parsing

### Architecture

```
lib/
├── cli.js           # Command-line argument parsing
├── fetcher.js       # IoC database fetching
├── file-discovery.js # Manifest and lockfile discovery
├── parsers.js       # JSON and Yarn.lock parsing
├── matchers.js      # Dependency matching logic
├── semver.js        # Semver parsing and comparison (zero-dependency)
├── formatters.js    # Human and JSON output formatting
└── bulk/
    ├── bulk-scanner.js  # Bulk scan orchestration
    └── logger.js        # Capturing logger for bulk mode

npm-scan.js          # Main entry point
```

## License

MIT

---

**Stay safe. Scan your dependencies. Trust no one.** 🔒
