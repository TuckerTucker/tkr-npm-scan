package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/formatter"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/scanner"
)

var (
	// Persistent flags
	pathFlag         string
	jsonFlag         bool
	verboseFlag      bool
	csvURLFlag       string
	lockfileOnlyFlag bool
)

var rootCmd = &cobra.Command{
	Use:   "npm-scan [path]",
	Short: "Scan npm projects for compromised packages",
	Long: `npm-scan is a vulnerability scanner for npm packages.
It checks your npm projects against an IoC (Indicators of Compromise) database
to detect malicious packages that may have been compromised.

The scanner supports three types of detections:
  - DIRECT: Exact version matches in package.json
  - TRANSITIVE: Resolved packages in lockfiles
  - POTENTIAL: Version ranges that could resolve to vulnerable versions`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	// Define flags
	rootCmd.Flags().StringVarP(&pathFlag, "path", "p", ".", "Path to scan (default: current directory)")
	rootCmd.Flags().BoolVar(&jsonFlag, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().StringVar(&csvURLFlag, "csv-url", "", "Custom IoC CSV URL (default: official repository)")
	rootCmd.Flags().BoolVar(&lockfileOnlyFlag, "lockfile-only", false, "Only scan lockfiles, skip package.json")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine the scan path
	scanPath := pathFlag
	if len(args) > 0 {
		scanPath = args[0]
	}

	// Verify path exists
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", scanPath)
	}

	// Configure scan options
	options := scanner.ScanOptions{
		Path:         scanPath,
		CSVURL:       csvURLFlag,
		LockfileOnly: lockfileOnlyFlag,
		Verbose:      verboseFlag,
		Context:      context.Background(),
	}

	// Run the scan
	result, err := scanner.RunScan(options)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Format and print results
	if jsonFlag {
		output, err := formatter.FormatJSON(result)
		if err != nil {
			return fmt.Errorf("failed to format JSON output: %w", err)
		}
		fmt.Println(output)
	} else {
		output := formatter.FormatHuman(result)
		fmt.Print(output)
	}

	// Determine exit code
	// 0 = clean (no vulnerabilities)
	// 1 = vulnerabilities found
	// 2 = error (already handled by returning error above)
	if len(result.Matches) > 0 {
		os.Exit(1)
	}

	return nil
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}
