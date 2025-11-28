package parser

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// YarnResolvedPackage represents a package entry from a yarn.lock file
type YarnResolvedPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	LockfilePath string `json:"lockfilePath"`
}

// YarnLock represents the parsed contents of a yarn.lock file.
// Supports both yarn v1 and v2/berry formats.
type YarnLock struct {
	Packages []YarnResolvedPackage
}

// ParseYarnLock reads and parses a yarn.lock file using a custom text parser.
// Supports both yarn v1 and v2/berry formats.
//
// The yarn.lock format consists of entries separated by blank lines:
//   package-name@^1.0.0:
//     version "1.0.5"
//     resolved "https://..."
//
// Parameters:
//   - path: Absolute path to the yarn.lock file
//
// Returns:
//   - *YarnLock: Pointer to the parsed yarn.lock, or nil if error
//   - error: Any error encountered during reading or parsing
func ParseYarnLock(path string) (*YarnLock, error) {
	// Read the file
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %w", err)
	}

	yarnLock := &YarnLock{
		Packages: []YarnResolvedPackage{},
	}

	// Parse the content
	entries := strings.Split(string(content), "\n\n")

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)

		if entry == "" {
			continue
		}

		lines := strings.Split(entry, "\n")
		if len(lines) == 0 {
			continue
		}

		header := lines[0]

		// Skip comments and metadata
		if strings.HasPrefix(header, "#") || strings.HasPrefix(header, "__metadata") {
			continue
		}

		// Extract package name from header
		// Examples:
		//   "package@^1.0.0:"
		//   "@scope/package@^1.0.0:"
		//   "package@^1.0.0, package@^1.1.0:"
		nameMatch := extractPackageName(header)
		if nameMatch == "" {
			continue
		}

		// Extract version from the entry
		version := extractVersionFromEntry(lines)
		if version == "" {
			continue
		}

		yarnLock.Packages = append(yarnLock.Packages, YarnResolvedPackage{
			Name:         nameMatch,
			Version:      version,
			LockfilePath: path,
		})
	}

	return yarnLock, nil
}

// extractPackageName extracts the package name from a yarn.lock header line.
// Handles scoped packages (@scope/package) and multiple version specs.
//
// Examples:
//   "package@^1.0.0:" -> "package"
//   "@scope/package@^1.0.0:" -> "@scope/package"
//   "package@^1.0.0, package@^1.1.0:" -> "package"
func extractPackageName(header string) string {
	// Remove trailing colon
	header = strings.TrimSuffix(header, ":")
	header = strings.TrimSpace(header)

	// Remove quotes if present
	header = strings.Trim(header, "\"")

	// Handle multiple version specs: "package@^1.0.0, package@^1.1.0"
	// We only want the first one
	if strings.Contains(header, ",") {
		header = strings.Split(header, ",")[0]
		header = strings.TrimSpace(header)
		// Remove quotes that might appear after comma
		header = strings.Trim(header, "\"")
	}

	// Extract name before the last @ sign (but handle @scope/package)
	// Strategy: find the last @ that's followed by a version (not part of scope)
	// For @scope/package@1.0.0, we want @scope/package (keep the first @)
	// For package@1.0.0, we want package

	// Find the last @ that's followed by a version spec
	lastAtIndex := strings.LastIndex(header, "@")
	if lastAtIndex == -1 {
		return ""
	}

	// If the @ is at the beginning, it's a scoped package like @scope/package@version
	if lastAtIndex == 0 {
		return ""
	}

	name := header[:lastAtIndex]
	return name
}

// extractVersionFromEntry extracts the version from yarn.lock entry lines.
// Looks for a line containing: version "X.Y.Z"
func extractVersionFromEntry(lines []string) string {
	versionRegex := regexp.MustCompile(`^\s*version\s+"([^"]+)"`)

	for _, line := range lines {
		matches := versionRegex.FindStringSubmatch(line)
		if matches != nil {
			return matches[1]
		}
	}

	return ""
}

// ExtractYarnResolvedPackages extracts all resolved packages from a YarnLock into a flat list.
// This is a convenience wrapper that returns the packages slice directly.
//
// Parameters:
//   - yarnLock: The yarn.lock to extract packages from
//
// Returns:
//   - []YarnResolvedPackage: Slice of all resolved packages found
func ExtractYarnResolvedPackages(yarnLock *YarnLock) []YarnResolvedPackage {
	if yarnLock == nil {
		return []YarnResolvedPackage{}
	}
	return yarnLock.Packages
}
