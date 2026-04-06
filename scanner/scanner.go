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
		{"Admin Users", func() {
			CheckAdminUsers(pubDir, &findings)
		}},
		{"Database Scan", func() {
			CheckDatabase(pubDir, &findings)
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
