package formatter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatHuman_NoMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 5,
		LockfilesScanned: 2,
		PackagesChecked:  1923,
		Matches:          []Match{},
		Timestamp:        time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:         795,
	}

	output := FormatHuman(result)

	// Check for essential elements
	if !strings.Contains(output, "NPM VULNERABILITY SCAN RESULTS (shai-hulud)") {
		t.Error("expected header in output")
	}
	if !strings.Contains(output, "SCAN SUMMARY") {
		t.Error("expected SCAN SUMMARY section")
	}
	if !strings.Contains(output, "✓ NO VULNERABILITIES FOUND") {
		t.Error("expected clean scan message")
	}
	if !strings.Contains(output, "795 packages") {
		t.Error("expected IoC count in output")
	}
	if !strings.Contains(output, "5 files") {
		t.Error("expected manifests count in output")
	}
	if !strings.Contains(output, "2 files") {
		t.Error("expected lockfiles count in output")
	}
}

func TestFormatHuman_DirectMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  50,
		Matches: []Match{
			{
				PackageName: "vulnerable-pkg",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	output := FormatHuman(result)

	// Check for essential elements
	if !strings.Contains(output, "⚠ AFFECTED PACKAGES FOUND: 1") {
		t.Error("expected vulnerability found message")
	}
	if !strings.Contains(output, "DIRECT DEPENDENCIES (1)") {
		t.Error("expected DIRECT DEPENDENCIES section")
	}
	if !strings.Contains(output, "vulnerable-pkg@1.0.0") {
		t.Error("expected package name and version")
	}
	if !strings.Contains(output, "./package.json") {
		t.Error("expected location")
	}
	if !strings.Contains(output, "Exact version pin matches IoC") {
		t.Error("expected status message")
	}
}

func TestFormatHuman_TransitiveMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  50,
		Matches: []Match{
			{
				PackageName: "@accordproject/concerto-analysis",
				Version:     "3.24.1",
				Severity:    SeverityTransitive,
				Location:    "./package-lock.json",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	output := FormatHuman(result)

	// Check for essential elements
	if !strings.Contains(output, "TRANSITIVE DEPENDENCIES (1)") {
		t.Error("expected TRANSITIVE DEPENDENCIES section")
	}
	if !strings.Contains(output, "@accordproject/concerto-analysis@3.24.1") {
		t.Error("expected transitive package details")
	}
	if !strings.Contains(output, "Resolved:") {
		t.Error("expected 'Resolved:' label for transitive match")
	}
}

func TestFormatHuman_PotentialMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  50,
		Matches: []Match{
			{
				PackageName:  "vulnerable-pkg",
				Version:      "1.0.0",
				Severity:     SeverityPotential,
				Location:     "./package.json",
				DeclaredSpec: "^1.0.0",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	output := FormatHuman(result)

	// Check for essential elements
	if !strings.Contains(output, "POTENTIAL MATCHES (1)") {
		t.Error("expected POTENTIAL MATCHES section")
	}
	if !strings.Contains(output, "Range could resolve to affected version") {
		t.Error("expected potential match status")
	}
	if !strings.Contains(output, "^1.0.0") {
		t.Error("expected declared spec in output")
	}
}

func TestFormatHuman_MultipleMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 2,
		LockfilesScanned: 2,
		PackagesChecked:  100,
		Matches: []Match{
			{
				PackageName: "pkg-direct",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
			{
				PackageName: "pkg-transitive",
				Version:     "2.0.0",
				Severity:    SeverityTransitive,
				Location:    "./package-lock.json",
			},
			{
				PackageName:  "pkg-potential",
				Version:      "3.0.0",
				Severity:     SeverityPotential,
				Location:     "./package.json",
				DeclaredSpec: "^3.0.0",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	output := FormatHuman(result)

	// Check for all sections
	if !strings.Contains(output, "⚠ AFFECTED PACKAGES FOUND: 3") {
		t.Error("expected 3 vulnerabilities found")
	}
	if !strings.Contains(output, "DIRECT DEPENDENCIES (1)") {
		t.Error("expected DIRECT DEPENDENCIES section")
	}
	if !strings.Contains(output, "TRANSITIVE DEPENDENCIES (1)") {
		t.Error("expected TRANSITIVE DEPENDENCIES section")
	}
	if !strings.Contains(output, "POTENTIAL MATCHES (1)") {
		t.Error("expected POTENTIAL MATCHES section")
	}
}

func TestFormatHuman_ContainsBoxDrawing(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  10,
		Matches:          []Match{},
		Timestamp:        time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:         795,
	}

	output := FormatHuman(result)

	// Check for box drawing characters
	if !strings.Contains(output, "╔") || !strings.Contains(output, "╚") {
		t.Error("expected box drawing characters")
	}
	if !strings.Contains(output, "║") {
		t.Error("expected vertical box drawing character")
	}
	if !strings.Contains(output, "────") {
		t.Error("expected horizontal separator")
	}
}

func TestFormatJSON_NoMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 5,
		LockfilesScanned: 2,
		PackagesChecked:  1923,
		Matches:          []Match{},
		Timestamp:        time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:         795,
	}

	output, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var decoded ScanResult
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify content
	if decoded.ManifestsScanned != 5 {
		t.Error("expected manifestsScanned to be 5")
	}
	if decoded.LockfilesScanned != 2 {
		t.Error("expected lockfilesScanned to be 2")
	}
	if decoded.IOCCount != 795 {
		t.Error("expected iocCount to be 795")
	}
	if len(decoded.Matches) != 0 {
		t.Error("expected no matches")
	}
}

func TestFormatJSON_WithMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  50,
		Matches: []Match{
			{
				PackageName: "vulnerable-pkg",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
			{
				PackageName:  "potential-pkg",
				Version:      "2.0.0",
				Severity:     SeverityPotential,
				Location:     "./package.json",
				DeclaredSpec: "^2.0.0",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	output, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var decoded ScanResult
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Verify content
	if len(decoded.Matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(decoded.Matches))
	}

	// Check first match
	if decoded.Matches[0].PackageName != "vulnerable-pkg" {
		t.Error("expected first match to be vulnerable-pkg")
	}
	if decoded.Matches[0].Severity != SeverityDirect {
		t.Error("expected first match severity to be DIRECT")
	}

	// Check second match
	if decoded.Matches[1].PackageName != "potential-pkg" {
		t.Error("expected second match to be potential-pkg")
	}
	if decoded.Matches[1].DeclaredSpec != "^2.0.0" {
		t.Error("expected second match to have declaredSpec")
	}
}

func TestFormatJSON_PrettyPrinted(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  10,
		Matches: []Match{
			{
				PackageName: "test-pkg",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  100,
	}

	output, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check for indentation (pretty-printed)
	if !strings.Contains(output, "  ") {
		t.Error("expected indentation in JSON output")
	}

	// Check for newlines
	if !strings.Contains(output, "\n") {
		t.Error("expected newlines in JSON output")
	}
}

func TestFormatJSON_NilMatches(t *testing.T) {
	result := &ScanResult{
		ManifestsScanned: 1,
		LockfilesScanned: 1,
		PackagesChecked:  10,
		Matches:          nil,
		Timestamp:        time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:         100,
	}

	output, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's valid JSON
	var decoded ScanResult
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// nil should be encoded as null and decoded as nil slice
	if decoded.Matches != nil && len(decoded.Matches) != 0 {
		t.Error("expected matches to be nil or empty slice")
	}
}

func TestFilterBySeverity(t *testing.T) {
	matches := []Match{
		{PackageName: "a", Severity: SeverityDirect},
		{PackageName: "b", Severity: SeverityTransitive},
		{PackageName: "c", Severity: SeverityDirect},
		{PackageName: "d", Severity: SeverityPotential},
		{PackageName: "e", Severity: SeverityTransitive},
	}

	directFiltered := filterBySeverity(matches, SeverityDirect)
	if len(directFiltered) != 2 {
		t.Errorf("expected 2 DIRECT matches, got %d", len(directFiltered))
	}

	transitiveFiltered := filterBySeverity(matches, SeverityTransitive)
	if len(transitiveFiltered) != 2 {
		t.Errorf("expected 2 TRANSITIVE matches, got %d", len(transitiveFiltered))
	}

	potentialFiltered := filterBySeverity(matches, SeverityPotential)
	if len(potentialFiltered) != 1 {
		t.Errorf("expected 1 POTENTIAL match, got %d", len(potentialFiltered))
	}
}

// Benchmark tests
func BenchmarkFormatHuman(b *testing.B) {
	result := &ScanResult{
		ManifestsScanned: 5,
		LockfilesScanned: 2,
		PackagesChecked:  1923,
		Matches: []Match{
			{
				PackageName: "pkg1",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
			{
				PackageName: "pkg2",
				Version:     "2.0.0",
				Severity:    SeverityTransitive,
				Location:    "./package-lock.json",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatHuman(result)
	}
}

func BenchmarkFormatJSON(b *testing.B) {
	result := &ScanResult{
		ManifestsScanned: 5,
		LockfilesScanned: 2,
		PackagesChecked:  1923,
		Matches: []Match{
			{
				PackageName: "pkg1",
				Version:     "1.0.0",
				Severity:    SeverityDirect,
				Location:    "./package.json",
			},
			{
				PackageName: "pkg2",
				Version:     "2.0.0",
				Severity:    SeverityTransitive,
				Location:    "./package-lock.json",
			},
		},
		Timestamp: time.Date(2025, 11, 28, 3, 50, 0, 0, time.UTC),
		IOCCount:  795,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatJSON(result)
	}
}
