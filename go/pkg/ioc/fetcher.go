package ioc

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// DefaultIoCURL is the default GitHub URL for the IoC CSV database
	DefaultIoCURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
)

// FetchIoCDatabase fetches the IoC CSV database from the given URL.
// It returns the raw CSV data as bytes, which can then be parsed by NewDatabase.
//
// The CSV format is expected to be:
//
//	Package,Version
//	02-echo,= 0.0.7
//	@accordproject/concerto-analysis,= 3.24.1
//
// If url is empty, DefaultIoCURL is used.
func FetchIoCDatabase(url string) ([]byte, error) {
	if url == "" {
		url = DefaultIoCURL
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch IoC database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch IoC database: HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IoC database response: %w", err)
	}

	return data, nil
}

// ParseCSV parses IoC CSV data and returns package->versions mapping.
// The CSV format is expected to have a header row, then lines with:
// - Column 0: package name
// - Column 1: version specification (e.g., "= 0.0.7")
//
// The version specification is trimmed and the "= " prefix is removed.
// Malformed lines (missing columns or empty) are skipped.
func ParseCSV(data []byte) (map[string][]string, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))

	// Read header row (and skip it)
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return map[string][]string{}, nil // Empty file, return empty map
		}
		return nil, fmt.Errorf("read CSV header: %w", err)
	}

	iocMap := make(map[string][]string)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read CSV record: %w", err)
		}

		// Skip empty lines or lines with insufficient columns
		if len(record) < 2 {
			continue
		}

		packageName := strings.TrimSpace(record[0])
		versionSpec := strings.TrimSpace(record[1])

		if packageName == "" || versionSpec == "" {
			continue
		}

		// Strip "= " prefix from version (e.g., "= 0.0.7" -> "0.0.7")
		version := strings.TrimPrefix(versionSpec, "=")
		version = strings.TrimSpace(version)

		iocMap[packageName] = append(iocMap[packageName], version)
	}

	return iocMap, nil
}
