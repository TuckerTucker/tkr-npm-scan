// Package bulk provides concurrent bulk scanning capabilities for multiple npm project paths.
package bulk

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tuckertucker/tkr-npm-scan/go/pkg/formatter"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/scanner"
)

// BulkOptions configures bulk scan behavior.
type BulkOptions struct {
	// PathsFile is the path to a file containing newline-separated paths to scan
	PathsFile string

	// OutputDir is the directory where results will be written (timestamped subdirectory created)
	OutputDir string

	// NumWorkers is the number of concurrent workers (goroutines) to use
	NumWorkers int

	// CSVURL is the IoC database URL (passed to scanner)
	CSVURL string

	// LockfileOnly determines whether to skip manifests (passed to scanner)
	LockfileOnly bool

	// Context for cancellation
	Context context.Context
}

// BulkSummary represents the summary.json output for bulk scans.
type BulkSummary struct {
	StartTime        time.Time                  `json:"startTime"`
	EndTime          time.Time                  `json:"endTime"`
	Duration         string                     `json:"duration"`
	TotalPaths       int                        `json:"totalPaths"`
	SuccessfulScans  int                        `json:"successfulScans"`
	FailedScans      int                        `json:"failedScans"`
	TotalMatches     int                        `json:"totalMatches"`
	PathResults      map[string]*PathSummary    `json:"pathResults"`
}

// PathSummary represents the summary for a single scanned path.
type PathSummary struct {
	Path              string              `json:"path"`
	Status            string              `json:"status"` // "success" or "error"
	Error             string              `json:"error,omitempty"`
	ManifestsScanned  int                 `json:"manifestsScanned"`
	LockfilesScanned  int                 `json:"lockfilesScanned"`
	PackagesChecked   int                 `json:"packagesChecked"`
	MatchesFound      int                 `json:"matchesFound"`
	ResultFile        string              `json:"resultFile,omitempty"`
	OutputFile        string              `json:"outputFile,omitempty"`
}

// RunBulkScan executes bulk scanning for multiple paths concurrently.
// Results are written to a timestamped directory with individual result files
// and a summary.json file.
func RunBulkScan(options BulkOptions) error {
	startTime := time.Now()

	// Set defaults
	if options.NumWorkers == 0 {
		options.NumWorkers = 4 // Default to 4 concurrent workers
	}
	if options.OutputDir == "" {
		options.OutputDir = "results"
	}
	if options.Context == nil {
		options.Context = context.Background()
	}

	// Read paths from file
	paths, err := readPathsFile(options.PathsFile)
	if err != nil {
		return fmt.Errorf("failed to read paths file: %w", err)
	}

	if len(paths) == 0 {
		return fmt.Errorf("no paths found in %s", options.PathsFile)
	}

	fmt.Printf("Starting bulk scan of %d paths with %d workers...\n", len(paths), options.NumWorkers)

	// Create timestamped output directory
	timestamp := startTime.Format("20060102-150405")
	resultsDir := filepath.Join(options.OutputDir, timestamp)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	fmt.Printf("Results will be written to: %s\n\n", resultsDir)

	// Initialize worker pool
	pool := NewWorkerPool(options.NumWorkers)
	pool.Start()

	// Submit jobs in a separate goroutine to avoid blocking
	go func() {
		for _, path := range paths {
			job := ScanJob{
				Path: path,
				Options: scanner.ScanOptions{
					Path:         path,
					CSVURL:       options.CSVURL,
					LockfileOnly: options.LockfileOnly,
					Verbose:      false, // Worker will override this
					Context:      options.Context,
				},
			}
			if err := pool.Submit(job); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to submit job for %s: %v\n", path, err)
			}
		}
	}()

	// Collect results
	summary := &BulkSummary{
		StartTime:   startTime,
		PathResults: make(map[string]*PathSummary),
	}

	for i := 0; i < len(paths); i++ {
		select {
		case result := <-pool.Results():
			pathSummary := processResult(result, resultsDir)
			summary.PathResults[result.Job.Path] = pathSummary

			if pathSummary.Status == "success" {
				summary.SuccessfulScans++
				summary.TotalMatches += pathSummary.MatchesFound
			} else {
				summary.FailedScans++
			}

			fmt.Printf("[%d/%d] %s: %s\n", i+1, len(paths), result.Job.Path, pathSummary.Status)

		case <-options.Context.Done():
			pool.Close()
			return options.Context.Err()
		}
	}

	pool.Close()

	// Finalize summary
	summary.EndTime = time.Now()
	summary.Duration = summary.EndTime.Sub(summary.StartTime).String()
	summary.TotalPaths = len(paths)

	// Write summary.json
	summaryPath := filepath.Join(resultsDir, "summary.json")
	if err := writeSummary(summary, summaryPath); err != nil {
		return fmt.Errorf("failed to write summary: %w", err)
	}

	// Print final summary
	fmt.Printf("\n=== Bulk Scan Complete ===\n")
	fmt.Printf("Duration: %s\n", summary.Duration)
	fmt.Printf("Paths scanned: %d\n", summary.TotalPaths)
	fmt.Printf("Successful: %d\n", summary.SuccessfulScans)
	fmt.Printf("Failed: %d\n", summary.FailedScans)
	fmt.Printf("Total matches: %d\n", summary.TotalMatches)
	fmt.Printf("Results: %s\n", resultsDir)

	return nil
}

// readPathsFile reads paths from a newline-separated file.
func readPathsFile(pathsFile string) ([]string, error) {
	file, err := os.Open(pathsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			paths = append(paths, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return paths, nil
}

// processResult processes a scan result and writes output files.
func processResult(result ScanJobResult, resultsDir string) *PathSummary {
	summary := &PathSummary{
		Path: result.Job.Path,
	}

	// Sanitize path for filename
	sanitized := sanitizePath(result.Job.Path)

	if result.Error != nil {
		summary.Status = "error"
		summary.Error = result.Error.Error()

		// Write error log
		errorFile := filepath.Join(resultsDir, sanitized+".error.txt")
		os.WriteFile(errorFile, []byte(result.Error.Error()), 0644)
		summary.OutputFile = errorFile
		return summary
	}

	summary.Status = "success"

	// Type assert the result
	scanResult, ok := result.Result.(*formatter.ScanResult)
	if !ok {
		summary.Status = "error"
		summary.Error = "invalid result type"
		return summary
	}

	summary.ManifestsScanned = scanResult.ManifestsScanned
	summary.LockfilesScanned = scanResult.LockfilesScanned
	summary.PackagesChecked = scanResult.PackagesChecked
	summary.MatchesFound = len(scanResult.Matches)

	// Write JSON result
	resultFile := filepath.Join(resultsDir, sanitized+".json")
	resultJSON, _ := formatter.FormatJSON(scanResult)
	os.WriteFile(resultFile, []byte(resultJSON), 0644)
	summary.ResultFile = resultFile

	// Write output log
	outputFile := filepath.Join(resultsDir, sanitized+".log")
	os.WriteFile(outputFile, []byte(result.Output), 0644)
	summary.OutputFile = outputFile

	return summary
}

// sanitizePath converts a path to a safe filename.
// Examples: "/path/to/project" -> "path-to-project"
func sanitizePath(path string) string {
	sanitized := strings.ReplaceAll(path, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, "\\", "-")
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	sanitized = strings.Trim(sanitized, "-")
	if sanitized == "" {
		sanitized = "root"
	}
	return sanitized
}

// writeSummary writes the bulk summary to a JSON file.
func writeSummary(summary *BulkSummary, path string) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
