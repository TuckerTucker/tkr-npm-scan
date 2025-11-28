package scanner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tuckertucker/tkr-npm-scan/go/pkg/parser"
)

// TestRunScan_Integration tests the full scanner orchestration
// using the node/ directory as a real-world test case.
func TestRunScan_Integration(t *testing.T) {
	// Path to the Node.js implementation (one level up from go/)
	nodePath := filepath.Join("..", "..", "..", "node")

	options := ScanOptions{
		Path:         nodePath,
		CSVURL:       "", // Use default
		LockfileOnly: false,
		Verbose:      testing.Verbose(),
		Context:      context.Background(),
	}

	result, err := RunScan(options)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	// Verify result structure
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Should have scanned at least 1 manifest
	if result.ManifestsScanned == 0 {
		t.Error("Expected at least 1 manifest scanned")
	}

	// Should have loaded IoC database
	if result.IOCCount == 0 {
		t.Error("Expected non-zero IoC count")
	}

	// Timestamp should be recent
	if time.Since(result.Timestamp) > 1*time.Minute {
		t.Error("Timestamp is not recent")
	}

	// Matches array should exist (even if empty)
	if result.Matches == nil {
		t.Error("Expected non-nil Matches array")
	}

	t.Logf("Scan results: %d manifests, %d lockfiles, %d packages checked, %d matches",
		result.ManifestsScanned,
		result.LockfilesScanned,
		result.PackagesChecked,
		len(result.Matches))
}

// TestRunScan_LockfileOnly tests lockfile-only scanning mode
func TestRunScan_LockfileOnly(t *testing.T) {
	nodePath := filepath.Join("..", "..", "..", "node")

	options := ScanOptions{
		Path:         nodePath,
		CSVURL:       "",
		LockfileOnly: true,
		Verbose:      false,
		Context:      context.Background(),
	}

	result, err := RunScan(options)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	// In lockfile-only mode, ManifestsScanned should be 0
	if result.ManifestsScanned != 0 {
		t.Errorf("Expected 0 manifests in lockfile-only mode, got %d", result.ManifestsScanned)
	}

	// Should still have scanned lockfiles
	if result.LockfilesScanned == 0 {
		t.Error("Expected at least 1 lockfile scanned")
	}
}

// TestRunScan_WithCancellation tests context cancellation
func TestRunScan_WithCancellation(t *testing.T) {
	nodePath := filepath.Join("..", "..", "..", "node")

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	options := ScanOptions{
		Path:         nodePath,
		CSVURL:       "",
		LockfileOnly: false,
		Verbose:      false,
		Context:      ctx,
	}

	_, err := RunScan(options)
	if err == nil {
		t.Error("Expected error due to cancellation, got nil")
	}

	// Note: Due to the timing of when cancellation is checked,
	// we might get either context.Canceled or a different error
	// if the scan completes before we check the context.
	// So we just verify that an error occurred.
}

// TestRunScan_NonExistentPath tests error handling for invalid paths
func TestRunScan_NonExistentPath(t *testing.T) {
	options := ScanOptions{
		Path:         "/nonexistent/path/that/does/not/exist",
		CSVURL:       "",
		LockfileOnly: false,
		Verbose:      false,
		Context:      context.Background(),
	}

	result, err := RunScan(options)

	// Should either return an error or return a result with zero files found
	if err == nil && result != nil {
		if result.ManifestsScanned > 0 || result.LockfilesScanned > 0 {
			t.Error("Expected no files to be scanned for nonexistent path")
		}
	}
}

// TestRunScan_EmptyDirectory tests scanning an empty directory
func TestRunScan_EmptyDirectory(t *testing.T) {
	// Use a temporary directory
	tmpDir := t.TempDir()

	options := ScanOptions{
		Path:         tmpDir,
		CSVURL:       "",
		LockfileOnly: false,
		Verbose:      false,
		Context:      context.Background(),
	}

	result, err := RunScan(options)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	// Should complete successfully with no files found
	if result.ManifestsScanned != 0 {
		t.Errorf("Expected 0 manifests in empty directory, got %d", result.ManifestsScanned)
	}

	if result.LockfilesScanned != 0 {
		t.Errorf("Expected 0 lockfiles in empty directory, got %d", result.LockfilesScanned)
	}

	if len(result.Matches) != 0 {
		t.Errorf("Expected 0 matches in empty directory, got %d", len(result.Matches))
	}

	// IoC database should still be loaded
	if result.IOCCount == 0 {
		t.Error("Expected IoC database to be loaded even for empty directory")
	}
}

// TestIsYarnLockfile tests the yarn.lock file detection
func TestIsYarnLockfile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "yarn.lock file",
			path:     "/path/to/yarn.lock",
			expected: true,
		},
		{
			name:     "package-lock.json file",
			path:     "/path/to/package-lock.json",
			expected: false,
		},
		{
			name:     "yarn.lock in subdirectory",
			path:     "/path/to/project/yarn.lock",
			expected: true,
		},
		{
			name:     "not a lockfile",
			path:     "/path/to/package.json",
			expected: false,
		},
		{
			name:     "short path",
			path:     "yarn",
			expected: false,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isYarnLockfile(tt.path)
			if result != tt.expected {
				t.Errorf("isYarnLockfile(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestConvertYarnToLockfile tests the conversion of Yarn packages to lockfile format
func TestConvertYarnToLockfile(t *testing.T) {
	resolvedPackages := []parser.ResolvedPackage{
		{
			Name:         "test-package",
			Version:      "1.0.0",
			LockfilePath: "/path/to/yarn.lock",
		},
		{
			Name:         "@scope/package",
			Version:      "2.0.0",
			LockfilePath: "/path/to/yarn.lock",
		},
	}

	lockfile := convertYarnToLockfile(resolvedPackages)

	if lockfile == nil {
		t.Fatal("Expected non-nil lockfile")
	}

	if lockfile.Version != 1 {
		t.Errorf("Expected version 1, got %d", lockfile.Version)
	}

	if len(lockfile.Packages) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(lockfile.Packages))
	}

	// Check that packages are correctly mapped
	if pkg, ok := lockfile.Packages["node_modules/test-package"]; !ok {
		t.Error("Expected test-package to be in Packages")
	} else if pkg.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", pkg.Version)
	}

	if pkg, ok := lockfile.Packages["node_modules/@scope/package"]; !ok {
		t.Error("Expected @scope/package to be in Packages")
	} else if pkg.Version != "2.0.0" {
		t.Errorf("Expected version 2.0.0, got %s", pkg.Version)
	}
}
