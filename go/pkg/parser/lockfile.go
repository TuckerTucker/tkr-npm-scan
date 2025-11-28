package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ResolvedPackage represents a package entry from a lockfile
type ResolvedPackage struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	LockfilePath  string `json:"lockfilePath"`
}

// PackageInfo represents package metadata in npm lockfile
type PackageInfo struct {
	Version      string                 `json:"version,omitempty"`
	Dependencies map[string]interface{} `json:"dependencies,omitempty"`
}

// Lockfile represents the parsed contents of an npm package-lock.json file.
// Supports both v2/v3 format (npm 7+) and v1 format (npm 5-6).
type Lockfile struct {
	Version  int                    `json:"lockfileVersion"`
	Packages map[string]PackageInfo `json:"packages,omitempty"`
	// For v1 format
	Dependencies map[string]PackageInfo `json:"dependencies,omitempty"`
}

// ParsePackageLock reads and parses an npm package-lock.json file.
// Supports both npm lockfile v2/v3 format (npm 7+) and v1 format (npm 5-6).
//
// Parameters:
//   - path: Absolute path to the package-lock.json file
//
// Returns:
//   - *Lockfile: Pointer to the parsed lockfile, or nil if error
//   - error: Any error encountered during reading or parsing
func ParsePackageLock(path string) (*Lockfile, error) {
	// Read the file
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	// Parse JSON
	var lockfile Lockfile
	if err := json.Unmarshal(content, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	return &lockfile, nil
}

// ExtractResolvedPackages extracts all resolved packages from a Lockfile into a flat list.
// Handles both v2/v3 format (packages field) and v1 format (dependencies field with recursion).
//
// Parameters:
//   - lockfile: The lockfile to extract packages from
//   - filePath: The source file path for reference
//
// Returns:
//   - []ResolvedPackage: Slice of all resolved packages found
func ExtractResolvedPackages(lockfile *Lockfile, filePath string) []ResolvedPackage {
	var packages []ResolvedPackage

	// Handle v2/v3 format (npm 7+)
	if lockfile.Packages != nil && len(lockfile.Packages) > 0 {
		for pkgPath, pkgInfo := range lockfile.Packages {
			// Skip root package entry
			if pkgPath == "" || pkgPath == "." {
				continue
			}

			if pkgInfo.Version == "" {
				continue
			}

			// Extract package name from path
			// node_modules/@scope/package -> @scope/package
			// node_modules/package -> package
			name := strings.TrimPrefix(pkgPath, "node_modules/")

			packages = append(packages, ResolvedPackage{
				Name:         name,
				Version:      pkgInfo.Version,
				LockfilePath: filePath,
			})
		}
	} else if lockfile.Dependencies != nil && len(lockfile.Dependencies) > 0 {
		// Handle v1 format (npm 5-6)
		extractDepsRecursive(lockfile.Dependencies, &packages, filePath)
	}

	return packages
}

// extractDepsRecursive recursively extracts dependencies from a map,
// handling nested dependencies in v1 lockfile format.
//
// Parameters:
//   - deps: The dependencies map to process
//   - packages: Pointer to the accumulating slice of resolved packages
//   - filePath: The source file path for reference
func extractDepsRecursive(deps map[string]PackageInfo, packages *[]ResolvedPackage, filePath string) {
	for name, info := range deps {
		if info.Version == "" {
			continue
		}

		*packages = append(*packages, ResolvedPackage{
			Name:         name,
			Version:      info.Version,
			LockfilePath: filePath,
		})

		// Recursively process nested dependencies if they exist
		if info.Dependencies != nil && len(info.Dependencies) > 0 {
			// Convert nested dependencies to PackageInfo map
			nestedDeps := make(map[string]PackageInfo)
			for k, v := range info.Dependencies {
				// Handle polymorphic nested dependencies
				if nested, ok := v.(map[string]interface{}); ok {
					version, _ := nested["version"].(string)
					nestedDeps[k] = PackageInfo{
						Version:      version,
						Dependencies: nested,
					}
				}
			}
			extractDepsRecursive(nestedDeps, packages, filePath)
		}
	}
}
