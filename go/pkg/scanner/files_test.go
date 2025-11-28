package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// setupTestDir creates a temporary directory structure for testing.
// Returns the root directory path and a cleanup function.
func setupTestDir(t *testing.T, structure map[string]string) (string, func()) {
	tmpDir := t.TempDir()

	for filePath := range structure {
		fullPath := filepath.Join(tmpDir, filePath)
		dir := filepath.Dir(fullPath)

		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}

		if err := os.WriteFile(fullPath, []byte("{}"), 0644); err != nil {
			t.Fatalf("failed to create file %s: %v", fullPath, err)
		}
	}

	return tmpDir, func() {
		os.RemoveAll(tmpDir)
	}
}

// TestFindManifests tests the FindManifests function with various directory structures.
func TestFindManifests(t *testing.T) {
	tests := []struct {
		name      string
		structure map[string]string
		expected  int
		wantErr   bool
	}{
		{
			name: "single package.json in root",
			structure: map[string]string{
				"package.json": "",
			},
			expected: 1,
			wantErr:  false,
		},
		{
			name: "multiple package.json files",
			structure: map[string]string{
				"package.json":           "",
				"subdir/package.json":    "",
				"subdir/nested/package.json": "",
			},
			expected: 3,
			wantErr:  false,
		},
		{
			name: "skip node_modules directory",
			structure: map[string]string{
				"package.json":                    "",
				"node_modules/package.json":       "",
				"node_modules/lib/package.json":   "",
				"subdir/package.json":             "",
				"subdir/node_modules/package.json": "",
			},
			expected: 2,
			wantErr:  false,
		},
		{
			name: "no package.json files",
			structure: map[string]string{
				"README.md": "",
				"src/index.js": "",
			},
			expected: 0,
			wantErr:  false,
		},
		{
			name: "empty directory",
			structure: map[string]string{},
			expected: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, cleanup := setupTestDir(t, tt.structure)
			defer cleanup()

			got, err := FindManifests(root)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindManifests() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.expected {
				t.Errorf("FindManifests() got %d files, want %d", len(got), tt.expected)
			}

			// Verify all returned paths are within the root
			for _, path := range got {
				if !isSubpath(root, path) {
					t.Errorf("FindManifests() returned path outside root: %s", path)
				}
			}
		})
	}
}

// TestFindLockfiles tests the FindLockfiles function with various directory structures.
func TestFindLockfiles(t *testing.T) {
	tests := []struct {
		name      string
		structure map[string]string
		expected  int
		wantErr   bool
	}{
		{
			name: "single package-lock.json",
			structure: map[string]string{
				"package-lock.json": "",
			},
			expected: 1,
			wantErr:  false,
		},
		{
			name: "single yarn.lock",
			structure: map[string]string{
				"yarn.lock": "",
			},
			expected: 1,
			wantErr:  false,
		},
		{
			name: "multiple lockfiles mixed",
			structure: map[string]string{
				"package-lock.json":           "",
				"yarn.lock":                   "",
				"subdir/package-lock.json":    "",
				"subdir/nested/yarn.lock":     "",
			},
			expected: 4,
			wantErr:  false,
		},
		{
			name: "skip node_modules directory",
			structure: map[string]string{
				"package-lock.json":                 "",
				"node_modules/package-lock.json":    "",
				"node_modules/lib/yarn.lock":        "",
				"subdir/yarn.lock":                  "",
				"subdir/node_modules/package-lock.json": "",
			},
			expected: 2,
			wantErr:  false,
		},
		{
			name: "no lockfiles",
			structure: map[string]string{
				"package.json": "",
				"README.md":    "",
			},
			expected: 0,
			wantErr:  false,
		},
		{
			name: "empty directory",
			structure: map[string]string{},
			expected: 0,
			wantErr:  false,
		},
		{
			name: "similar but different filenames",
			structure: map[string]string{
				"package-lock.json.bak": "",
				"yarn.lock.old":         "",
				"package.lock":          "",
				"lock.json":             "",
			},
			expected: 0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, cleanup := setupTestDir(t, tt.structure)
			defer cleanup()

			got, err := FindLockfiles(root)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindLockfiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.expected {
				t.Errorf("FindLockfiles() got %d files, want %d", len(got), tt.expected)
			}

			// Verify all returned paths are within the root
			for _, path := range got {
				if !isSubpath(root, path) {
					t.Errorf("FindLockfiles() returned path outside root: %s", path)
				}
			}
		})
	}
}

// TestFindManifeststAndLockfilesIntegration tests both functions working together.
func TestFindManifestsAndLockfilesIntegration(t *testing.T) {
	t.Run("combined search in monorepo structure", func(t *testing.T) {
		root, cleanup := setupTestDir(t, map[string]string{
			"package.json":                   "",
			"package-lock.json":              "",
			"packages/app/package.json":      "",
			"packages/app/yarn.lock":         "",
			"packages/lib/package.json":      "",
			"packages/lib/package-lock.json": "",
			"node_modules/package.json":      "",
			"packages/app/node_modules/yarn.lock": "",
		})
		defer cleanup()

		manifests, err := FindManifests(root)
		if err != nil {
			t.Fatalf("FindManifests() error: %v", err)
		}
		if len(manifests) != 3 {
			t.Errorf("FindManifests() got %d, want 3 (root, packages/app, packages/lib)", len(manifests))
		}

		lockfiles, err := FindLockfiles(root)
		if err != nil {
			t.Fatalf("FindLockfiles() error: %v", err)
		}
		if len(lockfiles) != 3 {
			t.Errorf("FindLockfiles() got %d, want 3 (root, packages/app, packages/lib)", len(lockfiles))
		}
	})
}

// TestFindManifestsOrdering tests that results are consistent.
func TestFindManifestsOrdering(t *testing.T) {
	t.Run("consistent ordering", func(t *testing.T) {
		root, cleanup := setupTestDir(t, map[string]string{
			"package.json":           "",
			"subdir/package.json":    "",
			"subdir/nested/package.json": "",
		})
		defer cleanup()

		// Call multiple times to ensure consistency
		first, err := FindManifests(root)
		if err != nil {
			t.Fatalf("FindManifests() error: %v", err)
		}

		second, err := FindManifests(root)
		if err != nil {
			t.Fatalf("FindManifests() error: %v", err)
		}

		// Sort both slices for comparison
		sort.Strings(first)
		sort.Strings(second)

		if len(first) != len(second) {
			t.Errorf("FindManifests() returned different lengths: %d vs %d", len(first), len(second))
		}

		for i, path := range first {
			if path != second[i] {
				t.Errorf("FindManifests() returned different paths at index %d: %s vs %s", i, path, second[i])
			}
		}
	})
}

// isSubpath checks if candidate is a subpath of root.
func isSubpath(root, candidate string) bool {
	abs, _ := filepath.Abs(root)
	relPath, err := filepath.Rel(abs, candidate)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(relPath) && relPath != ".."
}
