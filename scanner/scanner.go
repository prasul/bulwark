package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Scanner runs all WordPress security checks
type Scanner struct {
	Config Config
	vulnDB []VulnEntry
}

func New(cfg Config) *Scanner {
	return &Scanner{Config: cfg}
}

// Run executes the full scan across all sites
func (s *Scanner) Run() (*ScanSummary, error) {
	hostname, _ := os.Hostname()
	start := time.Now()

	summary := &ScanSummary{
		Hostname:     hostname,
		ScanDate:     start.Format("2006-01-02 15:04:05"),
		FailedChecks: make(map[string][]string),
	}

	// Host-level checks run once for the whole box, not once per site.
	CheckServerCron(&summary.HostFindings)

	// Load operator-supplied config once per run: extra pattern signatures
	// get merged straight into the built-in pattern lists, and the known-
	// vulnerability lists (hand-curated + the weekly Wordfence cache) get
	// held on the Scanner for CheckKnownVulnerabilities to consult per site.
	// A missing file is fine — every one of these is optional. A present
	// but malformed file is surfaced as a host-level Info finding instead
	// of aborting the whole scan.
	if err := loadCustomPatterns(s.Config.CustomPatternsPath); err != nil {
		summary.HostFindings = append(summary.HostFindings, Finding{
			Severity: Info,
			Check:    "Custom Patterns",
			Detail:   fmt.Sprintf("could not load %s: %v", s.Config.CustomPatternsPath, err),
			File:     s.Config.CustomPatternsPath,
		})
	}

	custom, err := loadVulnFile(s.Config.VulnConfigPath)
	if err != nil {
		summary.HostFindings = append(summary.HostFindings, Finding{
			Severity: Info,
			Check:    "Known Vulnerabilities",
			Detail:   fmt.Sprintf("could not load %s: %v", s.Config.VulnConfigPath, err),
			File:     s.Config.VulnConfigPath,
		})
	}

	cached, err := loadVulnFile(s.Config.VulnCachePath)
	if err != nil {
		summary.HostFindings = append(summary.HostFindings, Finding{
			Severity: Info,
			Check:    "Known Vulnerabilities",
			Detail:   fmt.Sprintf("could not load %s: %v (run `wpscan vulns update`?)", s.Config.VulnCachePath, err),
			File:     s.Config.VulnCachePath,
		})
	}
	s.vulnDB = append(custom, cached...)

	// Filter host-level findings down to the configured floor now, before
	// they're counted below — everything from here on (TotalIssues, the
	// printed summary, the HTML report) reflects what's actually shown.
	var hostHidden int
	summary.HostFindings, hostHidden = filterBySeverity(summary.HostFindings, s.Config.MinSeverity)
	summary.Hidden += hostHidden

	entries, err := os.ReadDir(s.Config.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read base dir %s: %w", s.Config.BaseDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		siteDir := filepath.Join(s.Config.BaseDir, entry.Name())
		pubDir := filepath.Join(siteDir, "public")
		if _, err := os.Stat(pubDir); os.IsNotExist(err) {
			continue
		}

		domain := entry.Name()
		summary.TotalSites++

		result := s.scanSite(domain, siteDir, pubDir)
		summary.Sites = append(summary.Sites, result)
		summary.Hidden += result.Hidden

		if result.HasIssues {
			summary.TotalIssues += len(result.Findings)
			for check := range result.ChecksFailed {
				summary.FailedChecks[check] = append(summary.FailedChecks[check], domain)
			}
		} else {
			summary.CleanSites++
		}
	}

	summary.Duration = time.Since(start)
	for _, hf := range summary.HostFindings {
		if hf.Severity == Critical || hf.Severity == Warning {
			summary.TotalIssues++
		}
	}
	return summary, nil
}

func (s *Scanner) scanSite(domain, siteDir, pubDir string) SiteResult {
	start := time.Now()
	result := SiteResult{
		Domain:       domain,
		SiteDir:      siteDir,
		ChecksFailed: make(map[string]bool),
	}

	type checkFunc struct {
		name string
		fn   func()
	}

	var findings []Finding

	checks := []checkFunc{
		{"Core Checksums", func() {
			CheckCoreChecksums(pubDir, &findings)
		}},
		{"File Placement", func() {
			CheckSuspiciousFiles(pubDir, &findings)
		}},
		{"Image Payload Scan", func() {
			CheckImageEmbeddedPHP(pubDir, &findings)
		}},
		{"Recently Modified", func() {
			CheckRecentlyModified(pubDir, s.Config.RecentDays, &findings)
		}},
		{"File Permissions", func() {
			CheckPermissions(pubDir, &findings)
		}},
		{"PHP Malware Scan", func() {
			CheckPHPMalware(pubDir, &findings)
		}},
		{"Theme Hook Injection", func() {
			CheckFunctionsInjection(pubDir, &findings)
		}},
		{"JS Injection", func() {
			CheckJSInjection(pubDir, &findings)
		}},
		{"mu-plugins Audit", func() {
			CheckMuPlugins(pubDir, &findings)
		}},
		{"Plugin Audit", func() {
			CheckPlugins(pubDir, s.Config.RecentDays, &findings)
		}},
		{"Known Vulnerabilities", func() {
			CheckKnownVulnerabilities(pubDir, s.vulnDB, &findings)
		}},
		{"Admin Users", func() {
			CheckAdminUsers(pubDir, &findings)
		}},
		{"Database Scan", func() {
			CheckDatabase(pubDir, &findings)
		}},
		{"PHP Malware Scan", func() {
			CheckCommentBackdoors(pubDir, &findings)
		}},
		{"Snippet Audit", func() {
			CheckHighRiskPluginsAndSnippets(pubDir, &findings)
		}},
	}

	for _, c := range checks {
		prevCount := len(findings)
		if s.Config.Verbose {
			fmt.Printf("  [%s] %s ... ", domain, c.name)
		}
		c.fn()
		newFindings := len(findings) - prevCount
		if s.Config.Verbose {
			if newFindings > 0 {
				fmt.Printf("✘ %d issue(s)\n", newFindings)
			} else {
				fmt.Println("✔")
			}
		}
	}

	// Apply the reporting floor last, after every check has had a chance to
	// run and score its own findings — HasIssues/ChecksFailed are computed
	// from what's actually kept, so they match what the report shows.
	findings, result.Hidden = filterBySeverity(findings, s.Config.MinSeverity)

	result.Findings = findings
	for _, f := range findings {
		if f.Severity == Critical || f.Severity == Warning {
			result.HasIssues = true
			result.ChecksFailed[f.Check] = true
		}
	}

	result.ScanDuration = time.Since(start)
	return result
}
