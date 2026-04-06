package scanner

import "time"

// Severity levels for findings
type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
	Info     Severity = "info"
)

// Finding represents a single security issue discovered during scanning
type Finding struct {
	Severity Severity
	Check    string
	Detail   string
	File     string // relative path if applicable
	Line     int    // line number if applicable
	Context  string // snippet of matched content
}

// SiteResult holds the complete scan results for one WordPress site
type SiteResult struct {
	Domain       string
	SiteDir      string
	Findings     []Finding
	HasIssues    bool
	ChecksFailed map[string]bool // which check categories failed
	ScanDuration time.Duration
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
}

// Config holds scanner configuration
type Config struct {
	BaseDir      string
	ReportDir    string
	RecentDays   int  // flag files modified within this many days (default 7)
	SkipPluginChecksums bool // skip plugin verify-checksums (default true)
	SkipThemeChecksums  bool // skip theme checksum downloads (default false)
	Verbose      bool
}

func DefaultConfig() Config {
	return Config{
		BaseDir:             "/home/nginx/domains",
		ReportDir:           "/usr/local/nginx/html/reports",
		RecentDays:          7,
		SkipPluginChecksums: true,
		SkipThemeChecksums:  false,
		Verbose:             false,
	}
}
