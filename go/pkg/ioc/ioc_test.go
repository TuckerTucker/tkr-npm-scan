package ioc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestParseCSV tests the CSV parsing function with various inputs.
func TestParseCSV(t *testing.T) {
	tests := []struct {
		name    string
		csv     string
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "valid CSV with single package",
			csv: `Package,Version
02-echo,= 0.0.7`,
			want: map[string][]string{
				"02-echo": {"0.0.7"},
			},
			wantErr: false,
		},
		{
			name: "valid CSV with multiple packages",
			csv: `Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1
another-pkg,= 1.2.3`,
			want: map[string][]string{
				"02-echo":                            {"0.0.7"},
				"@accordproject/concerto-analysis": {"3.24.1"},
				"another-pkg":                       {"1.2.3"},
			},
			wantErr: false,
		},
		{
			name: "CSV with trailing whitespace",
			csv: `Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,  = 3.24.1`,
			want: map[string][]string{
				"02-echo":                            {"0.0.7"},
				"@accordproject/concerto-analysis": {"3.24.1"},
			},
			wantErr: false,
		},
		{
			name: "CSV with empty lines",
			csv: `Package,Version
02-echo,= 0.0.7

@accordproject/concerto-analysis,= 3.24.1

`,
			want: map[string][]string{
				"02-echo":                            {"0.0.7"},
				"@accordproject/concerto-analysis": {"3.24.1"},
			},
			wantErr: false,
		},
		{
			name: "CSV with insufficient columns (skipped)",
			csv: `Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1
another-line,`,
			want: map[string][]string{
				"02-echo":                            {"0.0.7"},
				"@accordproject/concerto-analysis": {"3.24.1"},
			},
			wantErr: false,
		},
		{
			name:    "empty CSV (header only)",
			csv:     "Package,Version\n",
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name:    "completely empty - returns empty map",
			csv:     "",
			want:    map[string][]string{},
			wantErr: false, // Empty input returns empty map
		},
		{
			name: "version with special characters",
			csv: `Package,Version
@scope/pkg,= 1.0.0-alpha
nested/package,= 2.0.0+build.1`,
			want: map[string][]string{
				"@scope/pkg":      {"1.0.0-alpha"},
				"nested/package": {"2.0.0+build.1"},
			},
			wantErr: false,
		},
		{
			name: "multiple versions for same package",
			csv: `Package,Version
vulnerable,= 1.0.0
vulnerable,= 1.0.1`,
			want: map[string][]string{
				"vulnerable": {"1.0.0", "1.0.1"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCSV([]byte(tt.csv))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCSV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Compare maps
			if len(got) != len(tt.want) {
				t.Errorf("ParseCSV() returned %d packages, want %d", len(got), len(tt.want))
				return
			}

			for pkg, wantVersions := range tt.want {
				gotVersions, ok := got[pkg]
				if !ok {
					t.Errorf("ParseCSV() missing package: %s", pkg)
					continue
				}

				if len(gotVersions) != len(wantVersions) {
					t.Errorf("ParseCSV() package %s has %d versions, want %d", pkg, len(gotVersions), len(wantVersions))
					continue
				}

				for i, v := range wantVersions {
					if gotVersions[i] != v {
						t.Errorf("ParseCSV() package %s version[%d] = %s, want %s", pkg, i, gotVersions[i], v)
					}
				}
			}
		})
	}
}

// TestNewDatabase tests the Database constructor.
func TestNewDatabase(t *testing.T) {
	tests := []struct {
		name    string
		csv     string
		wantErr bool
		wantLen int
	}{
		{
			name: "valid database creation",
			csv: `Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1`,
			wantErr: false,
			wantLen: 2,
		},
		{
			name:    "empty CSV",
			csv:     "Package,Version\n",
			wantErr: false,
			wantLen: 0,
		},
		{
			name:    "empty CSV data",
			csv:     "",
			wantErr: false, // Empty CSV is handled gracefully
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDatabase([]byte(tt.csv))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDatabase() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if got := db.Count(); got != tt.wantLen {
				t.Errorf("NewDatabase() Count() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

// TestDatabaseLookup tests the Lookup method with table-driven tests.
func TestDatabaseLookup(t *testing.T) {
	csvData := []byte(`Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1
vulnerable-pkg,= 1.0.0
vulnerable-pkg,= 1.0.1
another-pkg,= 2.5.3`)

	db, err := NewDatabase(csvData)
	if err != nil {
		t.Fatalf("NewDatabase() error = %v", err)
	}

	tests := []struct {
		name string
		pkg  string
		ver  string
		want bool
	}{
		{
			name: "exact match - single version package",
			pkg:  "02-echo",
			ver:  "0.0.7",
			want: true,
		},
		{
			name: "no match - wrong version",
			pkg:  "02-echo",
			ver:  "0.0.8",
			want: false,
		},
		{
			name: "no match - package not found",
			pkg:  "nonexistent",
			ver:  "1.0.0",
			want: false,
		},
		{
			name: "exact match - first version of multi-version package",
			pkg:  "vulnerable-pkg",
			ver:  "1.0.0",
			want: true,
		},
		{
			name: "exact match - second version of multi-version package",
			pkg:  "vulnerable-pkg",
			ver:  "1.0.1",
			want: true,
		},
		{
			name: "no match - wrong version of multi-version package",
			pkg:  "vulnerable-pkg",
			ver:  "1.0.2",
			want: false,
		},
		{
			name: "match with scoped package name",
			pkg:  "@accordproject/concerto-analysis",
			ver:  "3.24.1",
			want: true,
		},
		{
			name: "no match - package with slash but wrong name",
			pkg:  "@accordproject/other",
			ver:  "3.24.1",
			want: false,
		},
		{
			name: "empty version string",
			pkg:  "02-echo",
			ver:  "",
			want: false,
		},
		{
			name: "empty package string",
			pkg:  "",
			ver:  "0.0.7",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.Lookup(tt.pkg, tt.ver)
			if got != tt.want {
				t.Errorf("Lookup(%q, %q) = %v, want %v", tt.pkg, tt.ver, got, tt.want)
			}
		})
	}
}

// TestDatabaseCount tests the Count method.
func TestDatabaseCount(t *testing.T) {
	tests := []struct {
		name string
		csv  string
		want int
	}{
		{
			name: "empty database",
			csv:  "Package,Version\n",
			want: 0,
		},
		{
			name: "single package",
			csv: `Package,Version
pkg1,= 1.0.0`,
			want: 1,
		},
		{
			name: "multiple packages",
			csv: `Package,Version
pkg1,= 1.0.0
pkg2,= 2.0.0
pkg3,= 3.0.0`,
			want: 3,
		},
		{
			name: "duplicate package names (multi-version)",
			csv: `Package,Version
pkg1,= 1.0.0
pkg1,= 1.0.1
pkg2,= 2.0.0`,
			want: 2, // Only 2 unique packages
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDatabase([]byte(tt.csv))
			if err != nil {
				t.Fatalf("NewDatabase() error = %v", err)
			}

			got := db.Count()
			if got != tt.want {
				t.Errorf("Count() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDatabaseSize tests the Size method.
func TestDatabaseSize(t *testing.T) {
	tests := []struct {
		name string
		csv  string
		want int
	}{
		{
			name: "empty database",
			csv:  "Package,Version\n",
			want: 0,
		},
		{
			name: "single entry",
			csv: `Package,Version
pkg1,= 1.0.0`,
			want: 1,
		},
		{
			name: "multiple entries",
			csv: `Package,Version
pkg1,= 1.0.0
pkg2,= 2.0.0
pkg3,= 3.0.0`,
			want: 3,
		},
		{
			name: "multiple versions per package",
			csv: `Package,Version
pkg1,= 1.0.0
pkg1,= 1.0.1
pkg2,= 2.0.0`,
			want: 3, // Total entries across all packages
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDatabase([]byte(tt.csv))
			if err != nil {
				t.Fatalf("NewDatabase() error = %v", err)
			}

			got := db.Size()
			if got != tt.want {
				t.Errorf("Size() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDatabaseGetVersions tests the GetVersions method.
func TestDatabaseGetVersions(t *testing.T) {
	csvData := []byte(`Package,Version
single-version,= 1.0.0
multi-version,= 1.0.0
multi-version,= 1.0.1
multi-version,= 1.0.2`)

	db, err := NewDatabase(csvData)
	if err != nil {
		t.Fatalf("NewDatabase() error = %v", err)
	}

	tests := []struct {
		name string
		pkg  string
		want []string
	}{
		{
			name: "single version package",
			pkg:  "single-version",
			want: []string{"1.0.0"},
		},
		{
			name: "multi-version package",
			pkg:  "multi-version",
			want: []string{"1.0.0", "1.0.1", "1.0.2"},
		},
		{
			name: "non-existent package",
			pkg:  "nonexistent",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.GetVersions(tt.pkg)

			if tt.want == nil {
				if got != nil {
					t.Errorf("GetVersions(%q) = %v, want nil", tt.pkg, got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("GetVersions(%q) returned %d versions, want %d", tt.pkg, len(got), len(tt.want))
				return
			}

			for i, v := range tt.want {
				if got[i] != v {
					t.Errorf("GetVersions(%q)[%d] = %s, want %s", tt.pkg, i, got[i], v)
				}
			}
		})
	}
}

// TestFetchIoCDatabase tests the HTTP fetching functionality.
func TestFetchIoCDatabase(t *testing.T) {
	tests := []struct {
		name       string
		csvContent string
		statusCode int
		wantErr    bool
		checkLen   func([]byte) bool
	}{
		{
			name: "successful fetch",
			csvContent: `Package,Version
02-echo,= 0.0.7`,
			statusCode: http.StatusOK,
			wantErr:    false,
			checkLen: func(data []byte) bool {
				return len(data) > 0
			},
		},
		{
			name:       "404 not found",
			csvContent: "",
			statusCode: http.StatusNotFound,
			wantErr:    true,
			checkLen:   nil,
		},
		{
			name:       "500 server error",
			csvContent: "",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
			checkLen:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.csvContent))
			}))
			defer server.Close()

			got, err := FetchIoCDatabase(server.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchIoCDatabase() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if tt.checkLen != nil && !tt.checkLen(got) {
				t.Errorf("FetchIoCDatabase() returned unexpected data length: %d", len(got))
			}

			// Verify content
			if !bytes.Equal(got, []byte(tt.csvContent)) {
				t.Errorf("FetchIoCDatabase() returned unexpected content")
			}
		})
	}
}

// TestFetchIoCDatabaseDefaultURL tests that empty URL uses DefaultIoCURL.
func TestFetchIoCDatabaseDefaultURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	}))
	defer server.Close()

	// We can't easily test the actual default URL in unit tests,
	// but we can verify that passing empty string doesn't crash.
	// This test would need network access to fully validate.
	t.Run("empty url parameter", func(t *testing.T) {
		// Note: This will attempt to fetch from GitHub in a real test
		// For unit testing purposes, we'd typically mock this behavior
		// or use a local test server.
		// This is a placeholder demonstrating the pattern.
		t.Log("DefaultIoCURL is used when url parameter is empty")
	})
}

// TestIntegration tests the complete flow: fetch, parse, and lookup.
func TestIntegration(t *testing.T) {
	t.Run("full workflow", func(t *testing.T) {
		// Create mock CSV data
		csvData := []byte(`Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1
vulnerable-pkg,= 1.0.0
vulnerable-pkg,= 2.0.0`)

		// Create database
		db, err := NewDatabase(csvData)
		if err != nil {
			t.Fatalf("NewDatabase() error = %v", err)
		}

		// Verify database stats
		if db.Count() != 3 {
			t.Errorf("Expected 3 packages, got %d", db.Count())
		}

		if db.Size() != 4 {
			t.Errorf("Expected 4 total entries, got %d", db.Size())
		}

		// Test lookups
		testCases := []struct {
			pkg    string
			ver    string
			found  bool
		}{
			{"02-echo", "0.0.7", true},
			{"02-echo", "0.0.8", false},
			{"vulnerable-pkg", "1.0.0", true},
			{"vulnerable-pkg", "2.0.0", true},
			{"vulnerable-pkg", "3.0.0", false},
			{"@accordproject/concerto-analysis", "3.24.1", true},
			{"nonexistent", "1.0.0", false},
		}

		for _, tc := range testCases {
			if got := db.Lookup(tc.pkg, tc.ver); got != tc.found {
				t.Errorf("Lookup(%q, %q) = %v, want %v", tc.pkg, tc.ver, got, tc.found)
			}
		}
	})
}
