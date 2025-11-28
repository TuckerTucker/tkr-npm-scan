package bulk

import (
	"context"
	"fmt"

	"github.com/tuckertucker/tkr-npm-scan/go/pkg/scanner"
)

// WorkerPool manages concurrent scan execution using goroutines.
type WorkerPool struct {
	numWorkers int
	jobs       chan ScanJob
	results    chan ScanJobResult
	ctx        context.Context
	cancel     context.CancelFunc
}

// ScanJob represents a single scan task for a worker.
type ScanJob struct {
	Path    string
	Options scanner.ScanOptions
}

// ScanJobResult contains the result of a scan job.
type ScanJobResult struct {
	Job    ScanJob
	Result interface{}
	Error  error
	Output string
}

// NewWorkerPool creates a new worker pool with the specified number of workers.
// The channels are unbuffered to prevent deadlocks - the caller must consume results
// as they are produced.
func NewWorkerPool(numWorkers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		numWorkers: numWorkers,
		jobs:       make(chan ScanJob),       // Unbuffered
		results:    make(chan ScanJobResult), // Unbuffered
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches the worker goroutines.
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.numWorkers; i++ {
		go wp.worker(i)
	}
}

// worker is the goroutine that processes scan jobs.
func (wp *WorkerPool) worker(id int) {
	for {
		select {
		case job, ok := <-wp.jobs:
			if !ok {
				return
			}

			// Create a capturing logger for this job
			logger := NewCapturingLogger()

			// Update job options to use worker context
			job.Options.Context = wp.ctx
			job.Options.Verbose = true // Always verbose for captured output

			// Capture output
			logger.Printf("\n[Worker %d] Scanning: %s\n", id, job.Path)

			// Run the scan
			result, err := scanner.RunScan(job.Options)

			// Send result
			wp.results <- ScanJobResult{
				Job:    job,
				Result: result,
				Error:  err,
				Output: logger.GetBuffer(),
			}

		case <-wp.ctx.Done():
			return
		}
	}
}

// Submit adds a job to the worker pool.
func (wp *WorkerPool) Submit(job ScanJob) error {
	select {
	case wp.jobs <- job:
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool closed")
	}
}

// Results returns the results channel.
func (wp *WorkerPool) Results() <-chan ScanJobResult {
	return wp.results
}

// Close stops all workers and closes channels.
func (wp *WorkerPool) Close() {
	close(wp.jobs)
	wp.cancel()
}
