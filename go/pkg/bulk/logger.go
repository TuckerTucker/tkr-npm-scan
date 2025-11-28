package bulk

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

// CapturingLogger captures output to both console and an internal buffer.
// This is used during bulk scanning to capture per-path scan output
// while still showing real-time progress to the user.
type CapturingLogger struct {
	buffer bytes.Buffer
	mu     sync.Mutex
	stdout io.Writer
}

// NewCapturingLogger creates a new logger that writes to both console and buffer.
func NewCapturingLogger() *CapturingLogger {
	return &CapturingLogger{
		stdout: os.Stdout,
	}
}

// Write implements io.Writer interface for capturing output.
func (l *CapturingLogger) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to buffer
	l.buffer.Write(p)

	// Write to stdout
	return l.stdout.Write(p)
}

// Printf formats and writes to both console and buffer.
func (l *CapturingLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.Write([]byte(msg))
}

// Println writes a line to both console and buffer.
func (l *CapturingLogger) Println(args ...interface{}) {
	msg := fmt.Sprintln(args...)
	l.Write([]byte(msg))
}

// GetBuffer returns the captured output as a string.
func (l *CapturingLogger) GetBuffer() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

// ClearBuffer clears the internal buffer.
func (l *CapturingLogger) ClearBuffer() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buffer.Reset()
}
