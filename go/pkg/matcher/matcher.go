// Package matcher provides vulnerability matching logic against IoC databases.
// It supports three types of matching: direct (exact version), transitive (resolved),
// and potential (semver range matches).
package matcher

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/formatter"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/ioc"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/parser"
)

// MatchDirect checks package.json dependencies for exact version matches against IoC database.
// Returns matches with DIRECT severity.
//
// This function checks declared dependencies where the version spec is an exact version
// (no semver operators like ^, ~, >=). It extracts all dependencies from the manifest
// and performs exact version lookups against the IoC database.
//
// Parameters:
//   - manifest: Parsed package.json manifest
//   - iocDB: IoC vulnerability database
//
// Returns:
//   - []formatter.Match: Slice of DIRECT matches found
func MatchDirect(manifest *parser.Manifest, iocDB *ioc.Database, filePath string) []formatter.Match {
	matches := []formatter.Match{}

	// Extract all dependencies from manifest
	deps := parser.ExtractDependencies(manifest, filePath)

	for _, dep := range deps {
		// Clean version spec and check if it's an exact version
		version := cleanVersionSpec(dep.VersionSpec)

		// Only match exact versions (no semver operators)
		if isExactVersion(dep.VersionSpec) {
			if iocDB.Lookup(dep.Name, version) {
				matches = append(matches, formatter.Match{
					PackageName: dep.Name,
					Version:     version,
					Severity:    formatter.SeverityDirect,
					Location:    dep.FilePath,
				})
			}
		}
	}

	return matches
}

// MatchTransitive checks package-lock.json resolved packages for exact matches against IoC database.
// Returns matches with TRANSITIVE severity.
//
// This function checks all resolved packages from lockfiles (package-lock.json or yarn.lock).
// These are concrete versions that have been resolved by the package manager.
//
// Parameters:
//   - lockfile: Parsed lockfile (package-lock.json or yarn.lock)
//   - iocDB: IoC vulnerability database
//
// Returns:
//   - []formatter.Match: Slice of TRANSITIVE matches found
func MatchTransitive(lockfile *parser.Lockfile, iocDB *ioc.Database, filePath string) []formatter.Match {
	matches := []formatter.Match{}

	// Extract all resolved packages from lockfile
	packages := parser.ExtractResolvedPackages(lockfile, filePath)

	for _, pkg := range packages {
		// Clean version and check against IoC database
		version := cleanVersionSpec(pkg.Version)

		if iocDB.Lookup(pkg.Name, version) {
			matches = append(matches, formatter.Match{
				PackageName: pkg.Name,
				Version:     version,
				Severity:    formatter.SeverityTransitive,
				Location:    pkg.LockfilePath,
			})
		}
	}

	return matches
}

// MatchPotential checks package.json semver ranges that could potentially resolve to vulnerable versions.
// Returns matches with POTENTIAL severity.
//
// This function analyzes version ranges (^1.0.0, ~2.0.0, >=3.0.0, etc.) and determines if any
// vulnerable versions in the IoC database would satisfy those ranges. This helps identify
// dependencies that might pull in vulnerable packages during installation.
//
// Parameters:
//   - manifest: Parsed package.json manifest
//   - iocDB: IoC vulnerability database
//
// Returns:
//   - []formatter.Match: Slice of POTENTIAL matches found
func MatchPotential(manifest *parser.Manifest, iocDB *ioc.Database, filePath string) []formatter.Match {
	matches := []formatter.Match{}

	// Extract all dependencies from manifest
	deps := parser.ExtractDependencies(manifest, filePath)

	for _, dep := range deps {
		// Skip exact versions (handled by MatchDirect)
		if isExactVersion(dep.VersionSpec) {
			continue
		}

		// Skip non-semver specs (file:, git:, http:, latest, *, etc.)
		if !isSemverRange(dep.VersionSpec) {
			continue
		}

		// Get all vulnerable versions for this package
		vulnerableVersions := iocDB.GetVersions(dep.Name)
		if vulnerableVersions == nil {
			continue
		}

		// Check if any vulnerable version satisfies the range
		for _, vulnVer := range vulnerableVersions {
			if versionSatisfiesRange(vulnVer, dep.VersionSpec) {
				matches = append(matches, formatter.Match{
					PackageName:  dep.Name,
					Version:      vulnVer,
					Severity:     formatter.SeverityPotential,
					Location:     dep.FilePath,
					DeclaredSpec: dep.VersionSpec,
				})
			}
		}
	}

	return matches
}

// cleanVersionSpec removes common npm version prefixes and whitespace.
// Examples: "^1.0.0" -> "1.0.0", "~2.0.0" -> "2.0.0", " 3.0.0 " -> "3.0.0"
func cleanVersionSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	spec = strings.TrimPrefix(spec, "^")
	spec = strings.TrimPrefix(spec, "~")
	spec = strings.TrimPrefix(spec, ">=")
	spec = strings.TrimPrefix(spec, "<=")
	spec = strings.TrimPrefix(spec, ">")
	spec = strings.TrimPrefix(spec, "<")
	spec = strings.TrimPrefix(spec, "=")
	spec = strings.TrimSpace(spec)
	return spec
}

// isExactVersion determines if a version spec is an exact version (no semver operators).
// Examples: "1.0.0" -> true, "^1.0.0" -> false, "~2.0.0" -> false
func isExactVersion(spec string) bool {
	spec = strings.TrimSpace(spec)

	// Check for semver operators
	if strings.ContainsAny(spec, "^~><*|") {
		return false
	}

	// Check for non-semver specs
	if strings.HasPrefix(spec, "file:") ||
	   strings.HasPrefix(spec, "git:") ||
	   strings.HasPrefix(spec, "http:") ||
	   strings.HasPrefix(spec, "https:") ||
	   spec == "latest" ||
	   spec == "" {
		return false
	}

	// Try parsing as semver - if it fails, it's not an exact version
	_, err := semver.NewVersion(spec)
	return err == nil
}

// isSemverRange determines if a version spec is a valid semver range.
// Returns false for non-semver specs like file:, git:, http:, latest, *, etc.
func isSemverRange(spec string) bool {
	spec = strings.TrimSpace(spec)

	// Exclude non-semver specs
	if strings.HasPrefix(spec, "file:") ||
	   strings.HasPrefix(spec, "git:") ||
	   strings.HasPrefix(spec, "http:") ||
	   strings.HasPrefix(spec, "https:") ||
	   spec == "latest" ||
	   spec == "*" ||
	   spec == "" {
		return false
	}

	// Try parsing as a constraint - if it succeeds, it's a valid semver range
	_, err := semver.NewConstraint(spec)
	return err == nil
}

// versionSatisfiesRange checks if a version satisfies a semver range constraint.
// Handles npm semver quirks including ^, ~, >=, <=, >, <, and exact versions.
//
// Parameters:
//   - version: The version to check (e.g., "1.2.3")
//   - rangeSpec: The semver range (e.g., "^1.0.0", "~2.0.0", ">=3.0.0")
//
// Returns:
//   - bool: true if version satisfies the range, false otherwise
func versionSatisfiesRange(version, rangeSpec string) bool {
	// Parse the version
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}

	// Parse the constraint
	constraint, err := semver.NewConstraint(rangeSpec)
	if err != nil {
		// If constraint parsing fails, try exact match
		cleanSpec := cleanVersionSpec(rangeSpec)
		return version == cleanSpec
	}

	// Check if version satisfies constraint
	valid, errs := constraint.Validate(v)
	if len(errs) > 0 {
		return false
	}

	return valid
}

// DeduplicateMatches removes duplicate matches from the slice.
// A match is considered duplicate if it has the same PackageName, Version, and Severity.
// Useful when combining results from multiple sources.
func DeduplicateMatches(matches []formatter.Match) []formatter.Match {
	seen := make(map[string]bool)
	result := []formatter.Match{}

	for _, match := range matches {
		key := fmt.Sprintf("%s@%s:%s", match.PackageName, match.Version, match.Severity)
		if !seen[key] {
			seen[key] = true
			result = append(result, match)
		}
	}

	return result
}
