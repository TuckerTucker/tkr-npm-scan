package scanner

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// FindManifests finds all package.json files in the given root directory,
// skipping node_modules and other non-relevant directories.
//
// It uses filepath.WalkDir for efficient directory traversal.
// Returns a slice of absolute paths to found package.json files.
func FindManifests(root string) ([]string, error) {
	var manifests []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip node_modules directories
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}

		// Check if this is a package.json file
		if !d.IsDir() && d.Name() == "package.json" {
			manifests = append(manifests, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("find manifests: %w", err)
	}

	return manifests, nil
}

// FindLockfiles finds all lockfile files (package-lock.json, yarn.lock) in the given
// root directory, skipping node_modules and other non-relevant directories.
//
// It uses filepath.WalkDir for efficient directory traversal.
// Returns a slice of absolute paths to found lockfiles.
func FindLockfiles(root string) ([]string, error) {
	var lockfiles []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip node_modules directories
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}

		// Check if this is a lockfile
		if !d.IsDir() {
			name := d.Name()
			if name == "package-lock.json" || name == "yarn.lock" {
				lockfiles = append(lockfiles, path)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("find lockfiles: %w", err)
	}

	return lockfiles, nil
}
