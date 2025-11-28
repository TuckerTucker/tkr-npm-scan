package matcher

import (
	"testing"

	"github.com/tuckertucker/tkr-npm-scan/go/pkg/formatter"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/ioc"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/parser"
)

// setupTestDB creates a test IoC database with known vulnerable packages
func setupTestDB(t *testing.T) *ioc.Database {
	t.Helper()

	csvData := []byte(`Package,Version
lodash,= 4.17.19
lodash,= 4.17.20
express,= 4.16.0
@scope/pkg,= 1.0.0
@scope/pkg,= 1.0.1
react,= 16.8.0
axios,= 0.18.0
moment,= 2.29.1
underscore,= 1.9.0
jquery,= 3.3.1`)

	db, err := ioc.NewDatabase(csvData)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	return db
}

// TestMatchDirect tests exact version matching from package.json
func TestMatchDirect(t *testing.T) {
	db := setupTestDB(t)

	tests := []struct {
		name     string
		manifest *parser.Manifest
		filePath string
		expected int
		packages []string
	}{
		{
			name: "exact_match_single_dependency",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "4.17.19",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"lodash"},
		},
		{
			name: "exact_match_multiple_dependencies",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash":  "4.17.19",
					"express": "4.16.0",
				},
			},
			filePath: "/test/package.json",
			expected: 2,
			packages: []string{"lodash", "express"},
		},
		{
			name: "exact_match_scoped_package",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"@scope/pkg": "1.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"@scope/pkg"},
		},
		{
			name: "no_match_safe_version",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "4.17.21",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "no_match_caret_range",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "^4.17.19",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "no_match_tilde_range",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "~4.17.19",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "exact_match_dev_dependencies",
			manifest: &parser.Manifest{
				DevDependencies: map[string]string{
					"react": "16.8.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"react"},
		},
		{
			name: "exact_match_optional_dependencies",
			manifest: &parser.Manifest{
				OptionalDependencies: map[string]string{
					"axios": "0.18.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"axios"},
		},
		{
			name: "no_match_empty_manifest",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "no_match_non_semver_specs",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"pkg1": "file:../local",
					"pkg2": "git://github.com/user/repo.git",
					"pkg3": "latest",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := MatchDirect(tt.manifest, db, tt.filePath)

			if len(matches) != tt.expected {
				t.Errorf("Expected %d matches, got %d", tt.expected, len(matches))
			}

			// Verify all matches have DIRECT severity
			for _, match := range matches {
				if match.Severity != formatter.SeverityDirect {
					t.Errorf("Expected DIRECT severity, got %s", match.Severity)
				}

				// Verify package name is in expected list
				found := false
				for _, pkg := range tt.packages {
					if match.PackageName == pkg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected package in matches: %s", match.PackageName)
				}
			}
		})
	}
}

// TestMatchTransitive tests resolved package matching from lockfiles
func TestMatchTransitive(t *testing.T) {
	db := setupTestDB(t)

	tests := []struct {
		name     string
		lockfile *parser.Lockfile
		filePath string
		expected int
		packages []string
	}{
		{
			name: "match_single_resolved_package",
			lockfile: &parser.Lockfile{
				Version: 2,
				Packages: map[string]parser.PackageInfo{
					"node_modules/lodash": {
						Version: "4.17.19",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 1,
			packages: []string{"lodash"},
		},
		{
			name: "match_multiple_resolved_packages",
			lockfile: &parser.Lockfile{
				Version: 2,
				Packages: map[string]parser.PackageInfo{
					"node_modules/lodash": {
						Version: "4.17.19",
					},
					"node_modules/express": {
						Version: "4.16.0",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 2,
			packages: []string{"lodash", "express"},
		},
		{
			name: "match_scoped_package",
			lockfile: &parser.Lockfile{
				Version: 2,
				Packages: map[string]parser.PackageInfo{
					"node_modules/@scope/pkg": {
						Version: "1.0.0",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 1,
			packages: []string{"@scope/pkg"},
		},
		{
			name: "no_match_safe_version",
			lockfile: &parser.Lockfile{
				Version: 2,
				Packages: map[string]parser.PackageInfo{
					"node_modules/lodash": {
						Version: "4.17.21",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "skip_root_package",
			lockfile: &parser.Lockfile{
				Version: 2,
				Packages: map[string]parser.PackageInfo{
					"": {
						Version: "1.0.0",
					},
					"node_modules/lodash": {
						Version: "4.17.19",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 1,
			packages: []string{"lodash"},
		},
		{
			name: "match_v1_lockfile_format",
			lockfile: &parser.Lockfile{
				Version: 1,
				Dependencies: map[string]parser.PackageInfo{
					"moment": {
						Version: "2.29.1",
					},
				},
			},
			filePath: "/test/package-lock.json",
			expected: 1,
			packages: []string{"moment"},
		},
		{
			name: "no_match_empty_lockfile",
			lockfile: &parser.Lockfile{
				Version:  2,
				Packages: map[string]parser.PackageInfo{},
			},
			filePath: "/test/package-lock.json",
			expected: 0,
			packages: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := MatchTransitive(tt.lockfile, db, tt.filePath)

			if len(matches) != tt.expected {
				t.Errorf("Expected %d matches, got %d", tt.expected, len(matches))
			}

			// Verify all matches have TRANSITIVE severity
			for _, match := range matches {
				if match.Severity != formatter.SeverityTransitive {
					t.Errorf("Expected TRANSITIVE severity, got %s", match.Severity)
				}

				// Verify package name is in expected list
				found := false
				for _, pkg := range tt.packages {
					if match.PackageName == pkg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected package in matches: %s", match.PackageName)
				}
			}
		})
	}
}

// TestMatchPotential tests semver range matching
func TestMatchPotential(t *testing.T) {
	db := setupTestDB(t)

	tests := []struct {
		name     string
		manifest *parser.Manifest
		filePath string
		expected int
		packages []string
	}{
		{
			name: "caret_range_matches_vulnerable",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "^4.17.0",
				},
			},
			filePath: "/test/package.json",
			expected: 2, // Both 4.17.19 and 4.17.20 match ^4.17.0
			packages: []string{"lodash"},
		},
		{
			name: "tilde_range_matches_vulnerable",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"express": "~4.16.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"express"},
		},
		{
			name: "greater_than_matches_vulnerable",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"react": ">=16.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"react"},
		},
		{
			name: "range_does_not_match_vulnerable",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "^5.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "skip_exact_versions",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"lodash": "4.17.19",
				},
			},
			filePath: "/test/package.json",
			expected: 0, // Exact versions handled by MatchDirect
			packages: []string{},
		},
		{
			name: "skip_non_semver_specs",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"pkg1": "file:../local",
					"pkg2": "git://github.com/user/repo.git",
					"pkg3": "latest",
					"pkg4": "*",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
		{
			name: "scoped_package_range_match",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"@scope/pkg": "^1.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 2, // Both 1.0.0 and 1.0.1 match ^1.0.0
			packages: []string{"@scope/pkg"},
		},
		{
			name: "complex_range_multiple_operators",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"jquery": ">=3.0.0 <4.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 1,
			packages: []string{"jquery"},
		},
		{
			name: "no_vulnerable_versions_for_package",
			manifest: &parser.Manifest{
				Dependencies: map[string]string{
					"safe-package": "^1.0.0",
				},
			},
			filePath: "/test/package.json",
			expected: 0,
			packages: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := MatchPotential(tt.manifest, db, tt.filePath)

			if len(matches) != tt.expected {
				t.Errorf("Expected %d matches, got %d", tt.expected, len(matches))
				for _, m := range matches {
					t.Logf("  Match: %s@%s (spec: %s)", m.PackageName, m.Version, m.DeclaredSpec)
				}
			}

			// Verify all matches have POTENTIAL severity and DeclaredSpec
			for _, match := range matches {
				if match.Severity != formatter.SeverityPotential {
					t.Errorf("Expected POTENTIAL severity, got %s", match.Severity)
				}

				if match.DeclaredSpec == "" {
					t.Errorf("Expected DeclaredSpec to be set for POTENTIAL match")
				}

				// Verify package name is in expected list
				found := false
				for _, pkg := range tt.packages {
					if match.PackageName == pkg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected package in matches: %s", match.PackageName)
				}
			}
		})
	}
}

// TestCleanVersionSpec tests version spec cleaning helper
func TestCleanVersionSpec(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.0.0", "1.0.0"},
		{"^1.0.0", "1.0.0"},
		{"~2.0.0", "2.0.0"},
		{">=3.0.0", "3.0.0"},
		{"<=4.0.0", "4.0.0"},
		{">5.0.0", "5.0.0"},
		{"<6.0.0", "6.0.0"},
		{"=7.0.0", "7.0.0"},
		{" 8.0.0 ", "8.0.0"},
		{"  ^9.0.0  ", "9.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanVersionSpec(tt.input)
			if result != tt.expected {
				t.Errorf("cleanVersionSpec(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsExactVersion tests exact version detection
func TestIsExactVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1.0.0", true},
		{"2.3.4", true},
		{"10.20.30", true},
		{"^1.0.0", false},
		{"~2.0.0", false},
		{">=3.0.0", false},
		{"*", false},
		{"latest", false},
		{"file:../local", false},
		{"git://github.com/user/repo.git", false},
		{"http://example.com/package.tgz", false},
		{"https://example.com/package.tgz", false},
		{"", false},
		{">1.0.0", false},
		{"1.x", false},
		{"1.*", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isExactVersion(tt.input)
			if result != tt.expected {
				t.Errorf("isExactVersion(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsSemverRange tests semver range detection
func TestIsSemverRange(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"^1.0.0", true},
		{"~2.0.0", true},
		{">=3.0.0", true},
		{"1.0.0", true},
		{"1.x", true},
		{">1.0.0 <2.0.0", true},
		{"*", false},
		{"latest", false},
		{"file:../local", false},
		{"git://github.com/user/repo.git", false},
		{"http://example.com/package.tgz", false},
		{"https://example.com/package.tgz", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isSemverRange(tt.input)
			if result != tt.expected {
				t.Errorf("isSemverRange(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestVersionSatisfiesRange tests semver constraint validation
func TestVersionSatisfiesRange(t *testing.T) {
	tests := []struct {
		version   string
		rangeSpec string
		expected  bool
	}{
		{"1.0.0", "^1.0.0", true},
		{"1.5.0", "^1.0.0", true},
		{"2.0.0", "^1.0.0", false},
		{"2.0.1", "~2.0.0", true},
		{"2.1.0", "~2.0.0", false},
		{"3.0.0", ">=3.0.0", true},
		{"2.9.9", ">=3.0.0", false},
		{"1.0.0", "1.0.0", true},
		{"1.0.1", "1.0.0", false},
		{"4.17.19", "^4.17.0", true},
		{"4.17.20", "^4.17.0", true},
		{"4.18.0", "^4.17.0", true},
		{"5.0.0", "^4.17.0", false},
		{"3.3.1", ">=3.0.0 <4.0.0", true},
		{"4.0.0", ">=3.0.0 <4.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version+"_"+tt.rangeSpec, func(t *testing.T) {
			result := versionSatisfiesRange(tt.version, tt.rangeSpec)
			if result != tt.expected {
				t.Errorf("versionSatisfiesRange(%q, %q) = %v, expected %v",
					tt.version, tt.rangeSpec, result, tt.expected)
			}
		})
	}
}

// TestDeduplicateMatches tests duplicate removal
func TestDeduplicateMatches(t *testing.T) {
	matches := []formatter.Match{
		{PackageName: "lodash", Version: "4.17.19", Severity: formatter.SeverityDirect},
		{PackageName: "lodash", Version: "4.17.19", Severity: formatter.SeverityDirect}, // Duplicate
		{PackageName: "lodash", Version: "4.17.19", Severity: formatter.SeverityTransitive},
		{PackageName: "lodash", Version: "4.17.20", Severity: formatter.SeverityDirect},
		{PackageName: "express", Version: "4.16.0", Severity: formatter.SeverityPotential},
		{PackageName: "express", Version: "4.16.0", Severity: formatter.SeverityPotential}, // Duplicate
	}

	result := DeduplicateMatches(matches)

	// Should have 4 unique matches
	if len(result) != 4 {
		t.Errorf("Expected 4 unique matches, got %d", len(result))
	}

	// Verify uniqueness
	seen := make(map[string]bool)
	for _, match := range result {
		key := match.PackageName + "@" + match.Version + ":" + string(match.Severity)
		if seen[key] {
			t.Errorf("Found duplicate match: %s", key)
		}
		seen[key] = true
	}
}

// TestMatcherIntegration tests all three matchers working together
func TestMatcherIntegration(t *testing.T) {
	db := setupTestDB(t)

	manifest := &parser.Manifest{
		Dependencies: map[string]string{
			"lodash":  "4.17.19",     // DIRECT match
			"express": "^4.16.0",     // POTENTIAL match
			"react":   "^17.0.0",     // No match (range excludes 16.8.0)
		},
	}

	lockfile := &parser.Lockfile{
		Version: 2,
		Packages: map[string]parser.PackageInfo{
			"node_modules/lodash": {
				Version: "4.17.19", // TRANSITIVE match
			},
			"node_modules/express": {
				Version: "4.16.0", // TRANSITIVE match
			},
			"node_modules/react": {
				Version: "17.0.2", // No match (safe version)
			},
		},
	}

	filePath := "/test/package.json"
	lockPath := "/test/package-lock.json"

	directMatches := MatchDirect(manifest, db, filePath)
	transitiveMatches := MatchTransitive(lockfile, db, lockPath)
	potentialMatches := MatchPotential(manifest, db, filePath)

	if len(directMatches) != 1 {
		t.Errorf("Expected 1 DIRECT match, got %d", len(directMatches))
	}

	if len(transitiveMatches) != 2 {
		t.Errorf("Expected 2 TRANSITIVE matches, got %d", len(transitiveMatches))
	}

	if len(potentialMatches) != 1 {
		t.Errorf("Expected 1 POTENTIAL match, got %d", len(potentialMatches))
	}

	// Combine and deduplicate
	// We expect: 1 DIRECT (lodash@4.17.19) + 2 TRANSITIVE (lodash@4.17.19, express@4.16.0) + 1 POTENTIAL (express@4.16.0)
	// Total: 4 matches before dedup
	// After dedup: lodash@4.17.19 appears as both DIRECT and TRANSITIVE, express@4.16.0 appears as both TRANSITIVE and POTENTIAL
	// These are unique by (PackageName, Version, Severity), so all 4 should remain
	allMatches := append(directMatches, transitiveMatches...)
	allMatches = append(allMatches, potentialMatches...)

	if len(allMatches) != 4 {
		t.Errorf("Expected 4 total matches before dedup, got %d", len(allMatches))
	}

	uniqueMatches := DeduplicateMatches(allMatches)

	// All matches have unique (PackageName, Version, Severity) combinations
	if len(uniqueMatches) != 4 {
		t.Errorf("Expected 4 unique matches after dedup, got %d", len(uniqueMatches))
	}
}
