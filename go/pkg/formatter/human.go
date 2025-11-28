package formatter

import (
	"fmt"
	"strings"
)

// ANSI color codes
const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorYellow = "\x1b[33m"
	colorGreen  = "\x1b[32m"
	colorGray   = "\x1b[90m"
	colorBold   = "\x1b[1m"
)

// FormatHuman formats scan results as human-readable text with box drawing characters.
// Output matches the Node.js implementation style.
func FormatHuman(result *ScanResult) string {
	var b strings.Builder

	// Header
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s╔════════════════════════════════════════════════════════╗%s\n", colorBold, colorReset))
	b.WriteString(fmt.Sprintf("%s║  NPM VULNERABILITY SCAN RESULTS (shai-hulud)           ║%s\n", colorBold, colorReset))
	b.WriteString(fmt.Sprintf("%s╚════════════════════════════════════════════════════════╝%s\n", colorBold, colorReset))
	b.WriteString("\n")

	// Summary section
	b.WriteString(fmt.Sprintf("%sSCAN SUMMARY%s\n", colorBold, colorReset))
	b.WriteString(fmt.Sprintf("%s────────────────────────────────────────────────────────%s\n", colorGray, colorReset))
	b.WriteString(fmt.Sprintf("IoC Database:      %d packages\n", result.IOCCount))
	b.WriteString(fmt.Sprintf("Manifests Scanned: %d files\n", result.ManifestsScanned))
	b.WriteString(fmt.Sprintf("Lockfiles Scanned: %d files\n", result.LockfilesScanned))
	b.WriteString(fmt.Sprintf("Packages Checked:  %d\n", result.PackagesChecked))
	b.WriteString(fmt.Sprintf("Timestamp:         %s\n", result.Timestamp.Format("2006-01-02T15:04:05.000Z")))
	b.WriteString("\n")

	// Categorize matches by severity
	directMatches := filterBySeverity(result.Matches, SeverityDirect)
	transitiveMatches := filterBySeverity(result.Matches, SeverityTransitive)
	potentialMatches := filterBySeverity(result.Matches, SeverityPotential)

	// Results section
	if len(result.Matches) == 0 {
		b.WriteString(fmt.Sprintf("%s%s✓ NO VULNERABILITIES FOUND%s\n", colorGreen, colorBold, colorReset))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%sAll packages appear safe.%s\n", colorGreen, colorReset))
	} else {
		b.WriteString(fmt.Sprintf("%s%s⚠ AFFECTED PACKAGES FOUND: %d%s\n", colorRed, colorBold, len(result.Matches), colorReset))
		b.WriteString("\n")

		// Direct dependencies section
		if len(directMatches) > 0 {
			b.WriteString(fmt.Sprintf("%s%sDIRECT DEPENDENCIES (%d)%s\n", colorRed, colorBold, len(directMatches), colorReset))
			b.WriteString(fmt.Sprintf("%s────────────────────────────────────────────────────────%s\n", colorGray, colorReset))

			for i, match := range directMatches {
				b.WriteString("\n")
				b.WriteString(fmt.Sprintf("%s%d. %s@%s%s\n", colorRed, i+1, match.PackageName, match.Version, colorReset))
				b.WriteString(fmt.Sprintf("   %sLocation:%s %s\n", colorGray, colorReset, match.Location))
				b.WriteString(fmt.Sprintf("   %sStatus:%s Exact version pin matches IoC\n", colorRed, colorReset))
				b.WriteString(fmt.Sprintf("   %sAction:%s Remove or update to a safe version immediately\n", colorYellow, colorReset))
			}

			b.WriteString("\n")
		}

		// Transitive dependencies section
		if len(transitiveMatches) > 0 {
			b.WriteString(fmt.Sprintf("%s%sTRANSITIVE DEPENDENCIES (%d)%s\n", colorRed, colorBold, len(transitiveMatches), colorReset))
			b.WriteString(fmt.Sprintf("%s────────────────────────────────────────────────────────%s\n", colorGray, colorReset))

			for i, match := range transitiveMatches {
				b.WriteString("\n")
				b.WriteString(fmt.Sprintf("%s%d. %s@%s%s\n", colorRed, i+1, match.PackageName, match.Version, colorReset))
				b.WriteString(fmt.Sprintf("   %sResolved:%s %s\n", colorGray, colorReset, match.Location))
				b.WriteString(fmt.Sprintf("   %sAction:%s Update parent packages to versions that don't depend on this package\n", colorYellow, colorReset))
			}

			b.WriteString("\n")
		}

		// Potential matches section
		if len(potentialMatches) > 0 {
			b.WriteString(fmt.Sprintf("%s%sPOTENTIAL MATCHES (%d)%s\n", colorYellow, colorBold, len(potentialMatches), colorReset))
			b.WriteString(fmt.Sprintf("%s────────────────────────────────────────────────────────%s\n", colorGray, colorReset))

			for i, match := range potentialMatches {
				b.WriteString("\n")
				b.WriteString(fmt.Sprintf("%s%d. %s%s\n", colorYellow, i+1, match.PackageName, colorReset))
				b.WriteString(fmt.Sprintf("   %sDeclared:%s %s (%s)\n", colorGray, colorReset, match.Location, match.DeclaredSpec))
				b.WriteString(fmt.Sprintf("   %sIoC Version:%s %s\n", colorGray, colorReset, match.Version))
				b.WriteString(fmt.Sprintf("   %sStatus:%s Range could resolve to affected version\n", colorYellow, colorReset))
				b.WriteString(fmt.Sprintf("   %sAction:%s Check lockfile to verify resolved version, update if affected\n", colorYellow, colorReset))
			}

			b.WriteString("\n")
		}
	}

	b.WriteString("\n")

	return b.String()
}

// filterBySeverity returns all matches with the specified severity level.
func filterBySeverity(matches []Match, severity Severity) []Match {
	var result []Match
	for _, m := range matches {
		if m.Severity == severity {
			result = append(result, m)
		}
	}
	return result
}
