// Package formatter provides output formatting for scan results.
// Supports human-readable and JSON output formats.
package formatter

import "time"

// Severity represents the classification level of a vulnerability match.
type Severity string

const (
	// SeverityDirect indicates an exact version match in package.json
	SeverityDirect Severity = "DIRECT"
	// SeverityTransitive indicates a resolved package in a lockfile
	SeverityTransitive Severity = "TRANSITIVE"
	// SeverityPotential indicates a version range that could resolve to a vulnerable version
	SeverityPotential Severity = "POTENTIAL"
)

// Match represents a single detected vulnerability.
type Match struct {
	PackageName  string    `json:"packageName"`
	Version      string    `json:"version"`
	Severity     Severity  `json:"severity"`
	Location     string    `json:"location"`
	DeclaredSpec string    `json:"declaredSpec,omitempty"` // For POTENTIAL matches
}

// ScanResult represents the complete results of a vulnerability scan.
type ScanResult struct {
	ManifestsScanned int       `json:"manifestsScanned"`
	LockfilesScanned int       `json:"lockfilesScanned"`
	PackagesChecked  int       `json:"packagesChecked"`
	Matches          []Match   `json:"matches"`
	Timestamp        time.Time `json:"timestamp"`
	IOCCount         int       `json:"iocCount"`
}
