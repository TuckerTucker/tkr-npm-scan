package ioc

import (
	"fmt"
	"sync"
)

// Database represents an in-memory IoC database of compromised packages.
// It stores package names mapped to lists of compromised versions.
type Database struct {
	ioc map[string][]string
	mu  sync.RWMutex
}

// NewDatabase creates a new Database from raw CSV data.
// The CSV data is parsed and stored in-memory for fast lookups.
//
// Example CSV format:
//
//	Package,Version
//	02-echo,= 0.0.7
//	@accordproject/concerto-analysis,= 3.24.1
//
// Returns an error if the CSV data cannot be parsed.
func NewDatabase(csvData []byte) (*Database, error) {
	iocMap, err := ParseCSV(csvData)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	return &Database{
		ioc: iocMap,
	}, nil
}

// Lookup checks if a package at a specific version exists in the IoC database.
// Returns true if the exact package and version combination is found, false otherwise.
// The lookup is case-sensitive and exact-match only.
//
// Example:
//
//	db.Lookup("02-echo", "0.0.7")        // true (if in database)
//	db.Lookup("02-echo", "0.0.8")        // false (version mismatch)
//	db.Lookup("nonexistent", "1.0.0")    // false (package not found)
func (d *Database) Lookup(pkg, ver string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	versions, exists := d.ioc[pkg]
	if !exists {
		return false
	}

	for _, v := range versions {
		if v == ver {
			return true
		}
	}

	return false
}

// Count returns the total number of unique packages in the IoC database.
func (d *Database) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.ioc)
}

// Size returns the total number of package-version entries in the database.
func (d *Database) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	size := 0
	for _, versions := range d.ioc {
		size += len(versions)
	}
	return size
}

// GetPackages returns all packages in the database (for testing/inspection).
// The returned slice contains the keys from the internal map.
func (d *Database) GetPackages() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	packages := make([]string, 0, len(d.ioc))
	for pkg := range d.ioc {
		packages = append(packages, pkg)
	}
	return packages
}

// GetVersions returns all compromised versions for a given package.
// Returns nil if the package is not in the database.
func (d *Database) GetVersions(pkg string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	versions, exists := d.ioc[pkg]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]string, len(versions))
	copy(result, versions)
	return result
}
