package scanner

import "time"

// Severity levels for findings
type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
	Info     Severity = "info"
)

// severityRank orders severities from least to most alarming, so they can
// be compared against a -min-severity floor. Anything not recognized (e.g.
// a zero-value Severity) ranks below Info — it gets filtered out rather
// than accidentally shown.
func severityRank(s Severity) int {
	switch s {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// filterBySeverity returns only the findings at or above min, preserving
// order. Used to implement Config.MinSeverity — findings below the floor
// are still computed (nothing about detection changes), they're just not
// included in what gets reported.
func filterBySeverity(findings []Finding, min Severity) ([]Finding, int) {
	if len(findings) == 0 {
		return findings, 0
	}
	threshold := severityRank(min)
	kept := make([]Finding, 0, len(findings))
	hidden := 0
	for _, f := range findings {
		if severityRank(f.Severity) >= threshold {
			kept = append(kept, f)
		} else {
			hidden++
		}
	}
	return kept, hidden
}

// Finding represents a single security issue discovered during scanning
type Finding struct {
	Severity Severity
	Check    string
	Detail   string
	File     string // relative path if applicable
	Line     int    // line number if applicable
	Context  string // snippet of matched content

	// Confidence and Signals come from the weighted pattern scanner (see
	// confidence.go) — Confidence is the aggregated score, Signals is how
	// many distinct patterns corroborated it. Both are 0 for findings from
	// deterministic checks (PHP-in-uploads, a rogue plugin dir, a known-CVE
	// version match) that were never "scored" in the first place — those
	// are just factually true or not, there's no ambiguity to grade.
	Confidence int
	Signals    int
}

// SiteResult holds the complete scan results for one WordPress site
type SiteResult struct {
	Domain       string
	SiteDir      string
	Findings     []Finding
	HasIssues    bool
	ChecksFailed map[string]bool // which check categories failed
	ScanDuration time.Duration
	Hidden       int // findings below Config.MinSeverity, computed but not reported
}

// ScanSummary holds the aggregate results across all sites
type ScanSummary struct {
	Hostname     string
	ScanDate     string
	TotalSites   int
	CleanSites   int
	TotalIssues  int
	Duration     time.Duration
	Sites        []SiteResult
	FailedChecks map[string][]string // check name -> list of affected domains
	HostFindings []Finding           // host-level checks that run once, not per-site (e.g. server crontab)
	Hidden       int                 // total findings below Config.MinSeverity across the whole run
}

// Config holds scanner configuration
type Config struct {
	BaseDir      string
	ReportDir    string
	RecentDays   int  // flag files modified within this many days (default 7)
	SkipPluginChecksums bool // skip plugin verify-checksums (default true)
	SkipThemeChecksums  bool // skip theme checksum downloads (default false)
	Verbose      bool

	// CustomPatternsPath points at a hand-edited JSON file of extra
	// regex/string signatures (same idea as scanner/patterns.go, just
	// operator-supplied). Missing file is not an error — every install
	// works with none of these configured.
	CustomPatternsPath string

	// VulnConfigPath points at a hand-edited JSON file of known-vulnerable
	// plugin/theme version ranges you've added yourself.
	VulnConfigPath string

	// VulnCachePath points at the machine-managed JSON cache written by
	// `wpscan vulns update` (see scanner/vulns_update.go). Never hand-edit
	// this one — it gets overwritten on every update.
	VulnCachePath string

	// MinSeverity is a hard floor below which findings are dropped from the
	// report entirely — for large fleets that genuinely don't want
	// Warning/Info noise at all. Detection itself is unaffected either way.
	// Defaults to Info (nothing dropped): Critical findings and everything
	// else are both shown, just tiered — Critical first and prominent,
	// Warning/Info afterward in a collapsed "additional context" section.
	// Set to Critical (via -min-severity) to go back to critical-only.
	MinSeverity Severity
}

func DefaultConfig() Config {
	return Config{
		BaseDir:             "/home/nginx/domains",
		ReportDir:           "/usr/local/nginx/html/reports",
		RecentDays:          7,
		SkipPluginChecksums: true,
		SkipThemeChecksums:  false,
		Verbose:             false,
		CustomPatternsPath:  "cfg/custom_patterns.json",
		VulnConfigPath:      "cfg/vulnerabilities.json",
		VulnCachePath:       "cfg/vulnerabilities.wordfence.json",
		MinSeverity:         Info,
	}
}
