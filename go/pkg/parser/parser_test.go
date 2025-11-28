package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParsePackageJSON tests parsing a valid package.json file
func TestParsePackageJSON(t *testing.T) {
	testPath := filepath.Join("testdata", "package.json")

	manifest, err := ParsePackageJSON(testPath)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if manifest == nil {
		t.Fatal("ParsePackageJSON returned nil manifest")
	}

	// Verify basic fields
	if manifest.Name != "test-project" {
		t.Errorf("Expected name 'test-project', got '%s'", manifest.Name)
	}

	if manifest.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", manifest.Version)
	}

	// Verify dependencies
	if len(manifest.Dependencies) != 3 {
		t.Errorf("Expected 3 dependencies, got %d", len(manifest.Dependencies))
	}

	if manifest.Dependencies["express"] != "^4.18.2" {
		t.Errorf("Expected express version '^4.18.2', got '%s'", manifest.Dependencies["express"])
	}

	// Verify dev dependencies
	if len(manifest.DevDependencies) != 2 {
		t.Errorf("Expected 2 dev dependencies, got %d", len(manifest.DevDependencies))
	}

	// Verify peer dependencies
	if len(manifest.PeerDependencies) != 1 {
		t.Errorf("Expected 1 peer dependency, got %d", len(manifest.PeerDependencies))
	}

	// Verify optional dependencies
	if len(manifest.OptionalDependencies) != 1 {
		t.Errorf("Expected 1 optional dependency, got %d", len(manifest.OptionalDependencies))
	}

	// Verify bundled dependencies
	if len(manifest.BundledDependencies) != 1 {
		t.Errorf("Expected 1 bundled dependency, got %d", len(manifest.BundledDependencies))
	}
}

// TestParsePackageJSON_NonExistent tests parsing a non-existent file
func TestParsePackageJSON_NonExistent(t *testing.T) {
	_, err := ParsePackageJSON("nonexistent/package.json")
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}
}

// TestParsePackageJSON_InvalidJSON tests parsing an invalid JSON file
func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	// Create a temporary file with invalid JSON
	tmpFile, err := os.CreateTemp("", "invalid-package-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("{invalid json}")
	tmpFile.Close()

	_, err = ParsePackageJSON(tmpFile.Name())
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestExtractDependencies tests extracting dependencies from a manifest
func TestExtractDependencies(t *testing.T) {
	testPath := filepath.Join("testdata", "package.json")

	manifest, err := ParsePackageJSON(testPath)
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	deps := ExtractDependencies(manifest, testPath)

	// Should have 3 + 2 + 1 + 1 + 1 = 8 dependencies total
	expectedCount := 8
	if len(deps) != expectedCount {
		t.Errorf("Expected %d dependencies, got %d", expectedCount, len(deps))
	}

	// Check that we have the expected dependency types
	types := make(map[string]int)
	for _, dep := range deps {
		types[dep.Type]++
	}

	if types["dependencies"] != 3 {
		t.Errorf("Expected 3 regular dependencies, got %d", types["dependencies"])
	}

	if types["devDependencies"] != 2 {
		t.Errorf("Expected 2 dev dependencies, got %d", types["devDependencies"])
	}

	if types["peerDependencies"] != 1 {
		t.Errorf("Expected 1 peer dependency, got %d", types["peerDependencies"])
	}

	// Check FilePath is set correctly
	for _, dep := range deps {
		if dep.FilePath != testPath {
			t.Errorf("Expected FilePath '%s', got '%s'", testPath, dep.FilePath)
		}
	}
}

// TestParsePackageLock_v3 tests parsing a v3 package-lock.json file
func TestParsePackageLock_v3(t *testing.T) {
	testPath := filepath.Join("testdata", "package-lock-v3.json")

	lockfile, err := ParsePackageLock(testPath)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if lockfile == nil {
		t.Fatal("ParsePackageLock returned nil lockfile")
	}

	if lockfile.Version != 3 {
		t.Errorf("Expected lockfile version 3, got %d", lockfile.Version)
	}

	if len(lockfile.Packages) == 0 {
		t.Fatal("Expected packages in lockfile, got none")
	}
}

// TestExtractResolvedPackages_v3 tests extracting packages from v3 lockfile
func TestExtractResolvedPackages_v3(t *testing.T) {
	testPath := filepath.Join("testdata", "package-lock-v3.json")

	lockfile, err := ParsePackageLock(testPath)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	packages := ExtractResolvedPackages(lockfile, testPath)

	// Should have 3 packages (root is skipped)
	expectedCount := 3
	if len(packages) != expectedCount {
		t.Errorf("Expected %d resolved packages, got %d", expectedCount, len(packages))
	}

	// Check for specific package
	found := false
	for _, pkg := range packages {
		if pkg.Name == "express" && pkg.Version == "4.18.2" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find express@4.18.2 in resolved packages")
	}

	// Check scoped package
	found = false
	for _, pkg := range packages {
		if pkg.Name == "@scope/package" && pkg.Version == "1.0.0" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find @scope/package@1.0.0 in resolved packages")
	}
}

// TestParsePackageLock_v1 tests parsing a v1 package-lock.json file
func TestParsePackageLock_v1(t *testing.T) {
	testPath := filepath.Join("testdata", "package-lock-v1.json")

	lockfile, err := ParsePackageLock(testPath)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	if lockfile == nil {
		t.Fatal("ParsePackageLock returned nil lockfile")
	}

	if lockfile.Version != 1 {
		t.Errorf("Expected lockfile version 1, got %d", lockfile.Version)
	}
}

// TestExtractResolvedPackages_v1 tests extracting packages from v1 lockfile with nested dependencies
func TestExtractResolvedPackages_v1(t *testing.T) {
	testPath := filepath.Join("testdata", "package-lock-v1.json")

	lockfile, err := ParsePackageLock(testPath)
	if err != nil {
		t.Fatalf("ParsePackageLock failed: %v", err)
	}

	packages := ExtractResolvedPackages(lockfile, testPath)

	// Should have 3 packages: express, lodash, and body-parser (nested under express)
	expectedCount := 3
	if len(packages) != expectedCount {
		t.Errorf("Expected %d resolved packages, got %d. Packages: %+v", expectedCount, len(packages), packages)
	}

	// Check for express
	found := false
	for _, pkg := range packages {
		if pkg.Name == "express" && pkg.Version == "4.18.2" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find express@4.18.2 in resolved packages")
	}

	// Check for nested dependency
	found = false
	for _, pkg := range packages {
		if pkg.Name == "body-parser" && pkg.Version == "1.20.0" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find body-parser@1.20.0 (nested dependency) in resolved packages")
	}
}

// TestParseYarnLock tests parsing a yarn.lock file
func TestParseYarnLock(t *testing.T) {
	testPath := filepath.Join("testdata", "yarn.lock")

	yarnLock, err := ParseYarnLock(testPath)
	if err != nil {
		t.Fatalf("ParseYarnLock failed: %v", err)
	}

	if yarnLock == nil {
		t.Fatal("ParseYarnLock returned nil yarnLock")
	}

	if len(yarnLock.Packages) == 0 {
		t.Fatal("Expected packages in yarn.lock, got none")
	}
}

// TestExtractYarnResolvedPackages tests extracting packages from yarn.lock
func TestExtractYarnResolvedPackages(t *testing.T) {
	testPath := filepath.Join("testdata", "yarn.lock")

	yarnLock, err := ParseYarnLock(testPath)
	if err != nil {
		t.Fatalf("ParseYarnLock failed: %v", err)
	}

	packages := ExtractYarnResolvedPackages(yarnLock)

	// The test file has 5 entries:
	// 1. @scope/package@^1.0.0
	// 2. express@^4.18.0
	// 3. express@^4.17.0
	// 4. lodash@^4.17.21, lodash@^4.17.0 (counts as 1 entry, 1 package)
	// 5. simple-package@*
	// Expected: 4 packages (lodash has multiple version specs but only one entry)
	if len(packages) != 4 {
		t.Errorf("Expected 4 packages, got %d. Packages: %v", len(packages), packages)
	}

	// Check for express (should be present with one of its versions)
	found := false
	for _, pkg := range packages {
		if pkg.Name == "express" && (pkg.Version == "4.18.2" || pkg.Version == "4.17.3") {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find express in yarn packages")
	}

	// Check for lodash
	found = false
	for _, pkg := range packages {
		if pkg.Name == "lodash" && pkg.Version == "4.17.21" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find lodash@4.17.21 in yarn packages")
	}

	// Check for simple-package
	found = false
	for _, pkg := range packages {
		if pkg.Name == "simple-package" && pkg.Version == "1.0.0" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find simple-package@1.0.0 in yarn packages")
	}
}

// TestParseYarnLock_NonExistent tests parsing a non-existent yarn.lock file
func TestParseYarnLock_NonExistent(t *testing.T) {
	_, err := ParseYarnLock("nonexistent/yarn.lock")
	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}
}

// TestExtractYarnResolvedPackages_Nil tests extracting packages from nil yarnLock
func TestExtractYarnResolvedPackages_Nil(t *testing.T) {
	packages := ExtractYarnResolvedPackages(nil)
	if len(packages) != 0 {
		t.Errorf("Expected 0 packages from nil yarnLock, got %d", len(packages))
	}
}

// TestExtractPackageName tests the package name extraction logic
func TestExtractPackageName(t *testing.T) {
	t.Run("simple package", func(t *testing.T) {
		name := extractPackageName("package@^1.0.0:")
		if name != "package" {
			t.Errorf("Expected 'package', got '%s'", name)
		}
	})

	t.Run("scoped package", func(t *testing.T) {
		name := extractPackageName("@scope/package@^1.0.0:")
		if name != "@scope/package" {
			t.Errorf("Expected '@scope/package', got '%s'", name)
		}
	})

	t.Run("multiple version specs", func(t *testing.T) {
		name := extractPackageName("lodash@^4.17.21, lodash@^4.17.0:")
		if name != "lodash" {
			t.Errorf("Expected 'lodash', got '%s'", name)
		}
	})

	t.Run("quoted header", func(t *testing.T) {
		name := extractPackageName("\"package@^1.0.0\":")
		if name != "package" {
			t.Errorf("Expected 'package', got '%s'", name)
		}
	})

	t.Run("quoted scoped package", func(t *testing.T) {
		name := extractPackageName("\"@scope/package@^1.0.0\":")
		if name != "@scope/package" {
			t.Errorf("Expected '@scope/package', got '%s'", name)
		}
	})
}

// TestExtractVersionFromEntry tests the version extraction logic
func TestExtractVersionFromEntry(t *testing.T) {
	t.Run("simple version", func(t *testing.T) {
		lines := []string{
			"package@^1.0.0:",
			"  version \"1.0.5\"",
			"  resolved \"https://...\"",
		}
		version := extractVersionFromEntry(lines)
		if version != "1.0.5" {
			t.Errorf("Expected '1.0.5', got '%s'", version)
		}
	})

	t.Run("version with hyphen", func(t *testing.T) {
		lines := []string{
			"package@^1.0.0:",
			"  version \"1.0.0-beta.1\"",
		}
		version := extractVersionFromEntry(lines)
		if version != "1.0.0-beta.1" {
			t.Errorf("Expected '1.0.0-beta.1', got '%s'", version)
		}
	})

	t.Run("no version found", func(t *testing.T) {
		lines := []string{
			"package@^1.0.0:",
			"  resolved \"https://...\"",
		}
		version := extractVersionFromEntry(lines)
		if version != "" {
			t.Errorf("Expected empty string, got '%s'", version)
		}
	})

	t.Run("version with extra whitespace", func(t *testing.T) {
		lines := []string{
			"package@^1.0.0:",
			"    version    \"2.0.0\"",
		}
		version := extractVersionFromEntry(lines)
		if version != "2.0.0" {
			t.Errorf("Expected '2.0.0', got '%s'", version)
		}
	})
}

// BenchmarkParsePackageJSON benchmarks parsing a package.json file
func BenchmarkParsePackageJSON(b *testing.B) {
	testPath := filepath.Join("testdata", "package.json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePackageJSON(testPath)
	}
}

// BenchmarkParsePackageLock benchmarks parsing a package-lock.json file
func BenchmarkParsePackageLock(b *testing.B) {
	testPath := filepath.Join("testdata", "package-lock-v3.json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePackageLock(testPath)
	}
}

// BenchmarkParseYarnLock benchmarks parsing a yarn.lock file
func BenchmarkParseYarnLock(b *testing.B) {
	testPath := filepath.Join("testdata", "yarn.lock")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseYarnLock(testPath)
	}
}

// BenchmarkExtractDependencies benchmarks extracting dependencies
func BenchmarkExtractDependencies(b *testing.B) {
	testPath := filepath.Join("testdata", "package.json")
	manifest, _ := ParsePackageJSON(testPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractDependencies(manifest, testPath)
	}
}

// BenchmarkExtractResolvedPackages benchmarks extracting resolved packages
func BenchmarkExtractResolvedPackages(b *testing.B) {
	testPath := filepath.Join("testdata", "package-lock-v3.json")
	lockfile, _ := ParsePackageLock(testPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractResolvedPackages(lockfile, testPath)
	}
}
