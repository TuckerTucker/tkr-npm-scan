package main

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/tuckertucker/tkr-npm-scan/go/pkg/bulk"
)

var (
	bulkWorkersFlag  int
	bulkOutputDirFlag string
)

var bulkCmd = &cobra.Command{
	Use:   "bulk <paths-file>",
	Short: "Scan multiple npm projects concurrently",
	Long: `Bulk scan mode scans multiple npm projects concurrently using a worker pool.

The paths file should contain one path per line. Comments (lines starting with #)
and blank lines are ignored.

Example paths.txt:
  # Production projects
  /path/to/project1
  /path/to/project2

  # Development projects
  /path/to/project3

Results are written to a timestamped directory with:
  - Individual JSON result files for each path
  - Log files capturing scan output
  - summary.json with aggregate statistics`,
	Args: cobra.ExactArgs(1),
	RunE: runBulkScan,
}

func init() {
	rootCmd.AddCommand(bulkCmd)

	bulkCmd.Flags().IntVar(&bulkWorkersFlag, "workers", 4, "Number of concurrent workers")
	bulkCmd.Flags().StringVar(&bulkOutputDirFlag, "output", "results", "Output directory for results")

	// Inherit CSV URL and lockfile-only flags from root
	bulkCmd.Flags().StringVar(&csvURLFlag, "csv-url", "", "Custom IoC CSV URL")
	bulkCmd.Flags().BoolVar(&lockfileOnlyFlag, "lockfile-only", false, "Only scan lockfiles")
}

func runBulkScan(cmd *cobra.Command, args []string) error {
	pathsFile := args[0]

	options := bulk.BulkOptions{
		PathsFile:    pathsFile,
		OutputDir:    bulkOutputDirFlag,
		NumWorkers:   bulkWorkersFlag,
		CSVURL:       csvURLFlag,
		LockfileOnly: lockfileOnlyFlag,
		Context:      context.Background(),
	}

	return bulk.RunBulkScan(options)
}
