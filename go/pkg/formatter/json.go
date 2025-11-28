package formatter

import (
	"encoding/json"
)

// FormatJSON formats scan results as JSON with 2-space indentation.
// Output is pretty-printed for readability.
func FormatJSON(result *ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
