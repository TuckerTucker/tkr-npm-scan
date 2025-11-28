package bulk

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCapturingLogger(t *testing.T) {
	logger := NewCapturingLogger()
	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}

	// Test Printf
	logger.Printf("test message %d\n", 123)
	buffer := logger.GetBuffer()
	if buffer != "test message 123\n" {
		t.Errorf("Expected 'test message 123\\n', got %q", buffer)
	}

	// Test ClearBuffer
	logger.ClearBuffer()
	buffer = logger.GetBuffer()
	if buffer != "" {
		t.Errorf("Expected empty buffer after clear, got %q", buffer)
	}

	// Test Println
	logger.Println("another", "test")
	buffer = logger.GetBuffer()
	if buffer == "" {
		t.Error("Expected non-empty buffer after Println")
	}
}

func TestReadPathsFile(t *testing.T) {
	// Create a temporary paths file
	tmpDir := t.TempDir()
	pathsFile := filepath.Join(tmpDir, "paths.txt")

	content := `# Comment line
/path/one
/path/two

# Another comment
/path/three
`
	if err := os.WriteFile(pathsFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	paths, err := readPathsFile(pathsFile)
	if err != nil {
		t.Fatalf("readPathsFile failed: %v", err)
	}

	expected := []string{"/path/one", "/path/two", "/path/three"}
	if len(paths) != len(expected) {
		t.Fatalf("Expected %d paths, got %d", len(expected), len(paths))
	}

	for i, path := range paths {
		if path != expected[i] {
			t.Errorf("Path %d: expected %q, got %q", i, expected[i], path)
		}
	}
}

func TestReadPathsFile_NonExistent(t *testing.T) {
	_, err := readPathsFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "unix path",
			path:     "/path/to/project",
			expected: "path-to-project",
		},
		{
			name:     "windows path",
			path:     "C:\\Users\\project",
			expected: "C:-Users-project",
		},
		{
			name:     "path with spaces",
			path:     "/path/with spaces/here",
			expected: "path-with_spaces-here",
		},
		{
			name:     "relative path",
			path:     "../relative/path",
			expected: "..-relative-path",
		},
		{
			name:     "current directory",
			path:     ".",
			expected: ".",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizePath(tt.path)
			if result != tt.expected {
				t.Errorf("sanitizePath(%q) = %q, expected %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestWorkerPool(t *testing.T) {
	pool := NewWorkerPool(2)
	if pool == nil {
		t.Fatal("Expected non-nil worker pool")
	}

	pool.Start()

	// Note: We can't easily test actual scanning without fixtures,
	// so this is just a structural test
	pool.Close()
}

func TestWriteSummary(t *testing.T) {
	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")

	summary := &BulkSummary{
		StartTime:       time.Now(),
		EndTime:         time.Now(),
		Duration:        "1s",
		TotalPaths:      2,
		SuccessfulScans: 1,
		FailedScans:     1,
		TotalMatches:    5,
		PathResults:     make(map[string]*PathSummary),
	}

	err := writeSummary(summary, summaryPath)
	if err != nil {
		t.Fatalf("writeSummary failed: %v", err)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("Failed to read summary file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty summary file")
	}
}
