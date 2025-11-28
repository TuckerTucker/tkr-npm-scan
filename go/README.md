# npm-scan (Go Implementation)

Go implementation of the npm vulnerability scanner for detecting compromised packages using the Shai-Hulud IoC database.

## Features

- **Fast and Efficient**: Concurrent scanning with worker pools
- **Zero Dependencies**: Static binary compilation
- **Cross-Platform**: Linux, macOS, Windows support
- **Multiple Detection Modes**:
  - DIRECT: Exact version matches in package.json
  - TRANSITIVE: Resolved packages in lockfiles
  - POTENTIAL: Version ranges that could resolve to vulnerable versions
- **Bulk Scanning**: Scan multiple projects concurrently
- **Flexible Output**: Human-readable or JSON formats

## Installation

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/tuckertucker/tkr-npm-scan/releases) page.

### Build from Source

Requirements:
- Go 1.21 or later

```bash
# Clone the repository
git clone https://github.com/tuckertucker/tkr-npm-scan.git
cd tkr-npm-scan/go

# Build
go build -o npm-scan ./cmd/npm-scan

# Or build with static linking for distribution
CGO_ENABLED=0 go build -ldflags="-s -w" -o npm-scan ./cmd/npm-scan
```

## Usage

### Single Scan

Scan the current directory:
```bash
npm-scan
```

Scan a specific path:
```bash
npm-scan /path/to/project
npm-scan --path /path/to/project
```

### Output Formats

Human-readable (default):
```bash
npm-scan
```

JSON output:
```bash
npm-scan --json
```

### Scan Options

Verbose output:
```bash
npm-scan --verbose
```

Only scan lockfiles (skip package.json):
```bash
npm-scan --lockfile-only
```

Use custom IoC database URL:
```bash
npm-scan --csv-url https://example.com/custom-ioc.csv
```

### Bulk Scanning

Scan multiple projects concurrently:

1. Create a paths file (`paths.txt`):
```
# Production projects
/path/to/project1
/path/to/project2

# Development projects
/path/to/project3
```

2. Run bulk scan:
```bash
npm-scan bulk paths.txt
```

3. Adjust concurrency:
```bash
npm-scan bulk paths.txt --workers 8
```

4. Specify output directory:
```bash
npm-scan bulk paths.txt --output ./scan-results
```

### Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected
- `2`: Error occurred during scan

## Examples

### Basic Scan
```bash
$ npm-scan ../node
Fetching IoC database...
Loaded 187 IoC entries
Discovering package.json files...
Found 1 package.json files

╔════════════════════════════════════════════════════════════╗
║  npm-scan - NPM Vulnerability Scanner (Go)                ║
╠════════════════════════════════════════════════════════════╣
║  Manifests scanned: 1                                      ║
║  Lockfiles scanned: 0                                      ║
║  Packages checked:  23                                     ║
║  IoC entries:       187                                    ║
║  Matches found:     0                                      ║
╚════════════════════════════════════════════════════════════╝

✓ No vulnerabilities detected
```

### JSON Output
```bash
$ npm-scan --json
{
  "manifestsScanned": 1,
  "lockfilesScanned": 0,
  "packagesChecked": 23,
  "matches": [],
  "timestamp": "2025-11-27T23:45:00Z",
  "iocCount": 187
}
```

### Bulk Scan
```bash
$ npm-scan bulk projects.txt --workers 4
Starting bulk scan of 3 paths with 4 workers...
Results will be written to: results/20251127-234500

[1/3] /path/to/project1: success
[2/3] /path/to/project2: success
[3/3] /path/to/project3: success

=== Bulk Scan Complete ===
Duration: 5.2s
Paths scanned: 3
Successful: 3
Failed: 0
Total matches: 0
Results: results/20251127-234500
```

## Development

### Project Structure
```
go/
├── cmd/
│   └── npm-scan/       # CLI entry point
│       ├── main.go
│       ├── root.go     # Root command
│       └── bulk.go     # Bulk command
├── pkg/
│   ├── bulk/           # Bulk scanning
│   ├── formatter/      # Output formatters
│   ├── ioc/            # IoC database
│   ├── matcher/        # Vulnerability matching
│   ├── parser/         # Package file parsers
│   └── scanner/        # Scan orchestration
└── go.mod
```

### Running Tests
```bash
# Run all tests
go test ./...

# Run with coverage
go test ./... -cover

# Run specific package tests
go test ./pkg/scanner -v

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Building

Development build:
```bash
go build -o npm-scan ./cmd/npm-scan
```

Production build (static binary):
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o npm-scan ./cmd/npm-scan
```

Cross-compilation:
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o npm-scan-linux ./cmd/npm-scan

# macOS
GOOS=darwin GOARCH=amd64 go build -o npm-scan-macos ./cmd/npm-scan

# Windows
GOOS=windows GOARCH=amd64 go build -o npm-scan.exe ./cmd/npm-scan
```

## Architecture

The Go implementation follows the Inversion of Control (IoC) design principle with clear separation of concerns:

1. **IoC Package**: Fetches and parses the vulnerability database
2. **Parser Package**: Parses package.json, package-lock.json, and yarn.lock files
3. **Matcher Package**: Matches packages against the IoC database using semver
4. **Scanner Package**: Orchestrates file discovery, parsing, and matching
5. **Formatter Package**: Formats output (human-readable, JSON)
6. **Bulk Package**: Manages concurrent scanning with worker pools
7. **CLI Package**: Cobra-based command-line interface

## Dependencies

- [Masterminds/semver](https://github.com/Masterminds/semver) - Semantic versioning
- [spf13/cobra](https://github.com/spf13/cobra) - CLI framework

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure:
- All tests pass (`go test ./...`)
- Code follows Go conventions (`go fmt`, `go vet`)
- Coverage remains >70%
