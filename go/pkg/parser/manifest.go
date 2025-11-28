package parser

import (
	"encoding/json"
	"fmt"
	"os"
)

// Dependency represents a single package dependency entry
type Dependency struct {
	Name        string `json:"name"`
	VersionSpec string `json:"versionSpec"`
	Type        string `json:"type"` // dependencies, devDependencies, etc.
	FilePath    string `json:"filePath"`
}

// Manifest represents the parsed contents of a package.json file
type Manifest struct {
	Name                 string            `json:"name,omitempty"`
	Version              string            `json:"version,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	BundledDependencies  []string          `json:"bundledDependencies,omitempty"`
}

// ParsePackageJSON reads and parses a package.json file at the given path.
// It returns a Manifest struct with all dependencies, or an error if the file
// cannot be read or parsed.
//
// Parameters:
//   - path: Absolute path to the package.json file
//
// Returns:
//   - *Manifest: Pointer to the parsed manifest, or nil if error
//   - error: Any error encountered during reading or parsing
func ParsePackageJSON(path string) (*Manifest, error) {
	// Read the file
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	// Parse JSON
	var manifest Manifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	return &manifest, nil
}

// ExtractDependencies extracts all dependencies from a Manifest into a flat list.
// Each dependency entry includes its name, version spec, and type.
//
// Parameters:
//   - manifest: The manifest to extract dependencies from
//   - filePath: The source file path for reference
//
// Returns:
//   - []Dependency: Slice of all dependencies found
func ExtractDependencies(manifest *Manifest, filePath string) []Dependency {
	var dependencies []Dependency

	depTypes := map[string]map[string]string{
		"dependencies":         manifest.Dependencies,
		"devDependencies":      manifest.DevDependencies,
		"peerDependencies":     manifest.PeerDependencies,
		"optionalDependencies": manifest.OptionalDependencies,
	}

	for depType, deps := range depTypes {
		if deps == nil {
			continue
		}

		for name, versionSpec := range deps {
			if name == "" || versionSpec == "" {
				continue
			}

			dependencies = append(dependencies, Dependency{
				Name:        name,
				VersionSpec: versionSpec,
				Type:        depType,
				FilePath:    filePath,
			})
		}
	}

	// Handle bundledDependencies as a string array
	// They don't have version specs, so use empty string
	if manifest.BundledDependencies != nil {
		for _, name := range manifest.BundledDependencies {
			if name == "" {
				continue
			}

			dependencies = append(dependencies, Dependency{
				Name:        name,
				VersionSpec: "",
				Type:        "bundledDependencies",
				FilePath:    filePath,
			})
		}
	}

	return dependencies
}
