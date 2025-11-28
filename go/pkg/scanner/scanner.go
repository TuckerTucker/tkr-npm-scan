// Package scanner orchestrates vulnerability scanning across npm projects.
// It coordinates file discovery, parsing, IoC database fetching, and vulnerability matching.
package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/tuckertucker/tkr-npm-scan/go/pkg/formatter"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/ioc"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/matcher"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/parser"
)

// ScanOptions configures the behavior of a vulnerability scan.
type ScanOptions struct {
	// Path is the root directory to scan for npm projects
	Path string

	// CSVURL is the URL to fetch the IoC database from.
	// If empty, the default URL will be used.
	CSVURL string

	// LockfileOnly determines whether to skip package.json manifest files
	// and only scan lockfiles (package-lock.json, yarn.lock).
	LockfileOnly bool

	// Verbose enables detailed logging during the scan.
	Verbose bool

	// Context for cancellation and timeout support
	Context context.Context
}

// RunScan orchestrates a complete vulnerability scan.
// It performs the following steps:
//  1. Fetch the IoC database from the specified URL
//  2. Discover package.json and lockfile files in the scan path
//  3. Parse all discovered files
//  4. Run vulnerability matching (direct, transitive, potential)
//  5. Aggregate and deduplicate results
//
// Returns a ScanResult containing all detected vulnerabilities, or an error if
// any critical step fails (e.g., network error, file not found).
func RunScan(options ScanOptions) (*formatter.ScanResult, error) {
	startTime := time.Now()

	// Set default context if not provided
	if options.Context == nil {
		options.Context = context.Background()
	}

	// Step 1: Fetch IoC database
	if options.Verbose {
		fmt.Printf("Fetching IoC database from %s...\n", options.CSVURL)
	}

	csvData, err := ioc.FetchIoCDatabase(options.CSVURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IoC database: %w", err)
	}

	iocDB, err := ioc.NewDatabase(csvData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IoC database: %w", err)
	}

	if options.Verbose {
		fmt.Printf("Loaded %d IoC entries\n", iocDB.Size())
	}

	// Step 2: Discover files
	var manifestPaths []string
	var lockfilePaths []string

	if !options.LockfileOnly {
		if options.Verbose {
			fmt.Printf("Discovering package.json files in %s...\n", options.Path)
		}
		manifestPaths, err = FindManifests(options.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to find manifests: %w", err)
		}
		if options.Verbose {
			fmt.Printf("Found %d package.json files\n", len(manifestPaths))
		}
	}

	if options.Verbose {
		fmt.Printf("Discovering lockfiles in %s...\n", options.Path)
	}
	lockfilePaths, err = FindLockfiles(options.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to find lockfiles: %w", err)
	}
	if options.Verbose {
		fmt.Printf("Found %d lockfiles\n", len(lockfilePaths))
	}

	// Step 3: Parse files and run matching
	var allMatches []formatter.Match
	packagesChecked := 0

	// Process manifests (unless lockfile-only mode)
	if !options.LockfileOnly {
		for _, manifestPath := range manifestPaths {
			// Check context for cancellation
			select {
			case <-options.Context.Done():
				return nil, options.Context.Err()
			default:
			}

			if options.Verbose {
				fmt.Printf("Parsing %s...\n", manifestPath)
			}

			manifest, err := parser.ParsePackageJSON(manifestPath)
			if err != nil {
				// Log error but continue scanning other files
				if options.Verbose {
					fmt.Printf("Warning: failed to parse %s: %v\n", manifestPath, err)
				}
				continue
			}

			// Extract dependencies for counting
			deps := parser.ExtractDependencies(manifest, manifestPath)
			packagesChecked += len(deps)

			// Run direct matching
			directMatches := matcher.MatchDirect(manifest, iocDB, manifestPath)
			allMatches = append(allMatches, directMatches...)

			// Run potential matching
			potentialMatches := matcher.MatchPotential(manifest, iocDB, manifestPath)
			allMatches = append(allMatches, potentialMatches...)
		}
	}

	// Process lockfiles
	for _, lockfilePath := range lockfilePaths {
		// Check context for cancellation
		select {
		case <-options.Context.Done():
			return nil, options.Context.Err()
		default:
		}

		if options.Verbose {
			fmt.Printf("Parsing %s...\n", lockfilePath)
		}

		// Determine lockfile type and parse accordingly
		var lockfile *parser.Lockfile
		var yarnLock *parser.YarnLock

		if isYarnLockfile(lockfilePath) {
			yarnLock, err = parser.ParseYarnLock(lockfilePath)
			if err != nil {
				if options.Verbose {
					fmt.Printf("Warning: failed to parse %s: %v\n", lockfilePath, err)
				}
				continue
			}

			// Extract resolved packages from yarn.lock
			yarnPackages := parser.ExtractYarnResolvedPackages(yarnLock)
			packagesChecked += len(yarnPackages)

			// Convert yarn packages to ResolvedPackage format
			var resolvedPackages []parser.ResolvedPackage
			for _, yp := range yarnPackages {
				resolvedPackages = append(resolvedPackages, parser.ResolvedPackage{
					Name:         yp.Name,
					Version:      yp.Version,
					LockfilePath: yp.LockfilePath,
				})
			}

			// Create a temporary lockfile structure for MatchTransitive
			tempLockfile := convertYarnToLockfile(resolvedPackages)
			transitiveMatches := matcher.MatchTransitive(tempLockfile, iocDB, lockfilePath)
			allMatches = append(allMatches, transitiveMatches...)
		} else {
			lockfile, err = parser.ParsePackageLock(lockfilePath)
			if err != nil {
				if options.Verbose {
					fmt.Printf("Warning: failed to parse %s: %v\n", lockfilePath, err)
				}
				continue
			}

			resolvedPackages := parser.ExtractResolvedPackages(lockfile, lockfilePath)
			packagesChecked += len(resolvedPackages)

			// Run transitive matching
			transitiveMatches := matcher.MatchTransitive(lockfile, iocDB, lockfilePath)
			allMatches = append(allMatches, transitiveMatches...)
		}
	}

	// Step 4: Deduplicate matches
	allMatches = matcher.DeduplicateMatches(allMatches)

	// Step 5: Build result
	result := &formatter.ScanResult{
		ManifestsScanned: len(manifestPaths),
		LockfilesScanned: len(lockfilePaths),
		PackagesChecked:  packagesChecked,
		Matches:          allMatches,
		Timestamp:        startTime,
		IOCCount:         iocDB.Size(),
	}

	if options.Verbose {
		duration := time.Since(startTime)
		fmt.Printf("\nScan completed in %v\n", duration)
		fmt.Printf("Found %d matches\n", len(allMatches))
	}

	return result, nil
}

// isYarnLockfile determines if a path points to a yarn.lock file.
func isYarnLockfile(path string) bool {
	return len(path) >= 9 && path[len(path)-9:] == "yarn.lock"
}

// convertYarnToLockfile converts resolved packages to a Lockfile structure
// for compatibility with MatchTransitive.
func convertYarnToLockfile(resolvedPackages []parser.ResolvedPackage) *parser.Lockfile {
	lockfile := &parser.Lockfile{
		Version:  1, // Use v1 format structure
		Packages: make(map[string]parser.PackageInfo),
	}

	for _, pkg := range resolvedPackages {
		// Create a node_modules path for consistency with npm lockfiles
		pkgPath := "node_modules/" + pkg.Name
		lockfile.Packages[pkgPath] = parser.PackageInfo{
			Version: pkg.Version,
		}
	}

	return lockfile
}
