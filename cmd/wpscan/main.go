package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/prasul/wpscan/report"
	"github.com/prasul/wpscan/scanner"
)

const version = "3.0.0"

func main() {
	cfg := scanner.DefaultConfig()

	flag.StringVar(&cfg.BaseDir, "base", cfg.BaseDir, "Base directory containing WordPress sites")
	flag.StringVar(&cfg.ReportDir, "report-dir", cfg.ReportDir, "Directory for HTML reports")
	flag.IntVar(&cfg.RecentDays, "recent-days", cfg.RecentDays, "Flag files modified within N days")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.Parse()

	// Terminal banner
	fmt.Printf("\n\033[1;36m╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║    WordPress Security Scanner v%s (Go)    ║\n", version)
	fmt.Printf("║    %s                ║\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("╚══════════════════════════════════════════════╝\033[0m\n\n")

	s := scanner.New(cfg)
	summary, err := s.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[1;31mError: %v\033[0m\n", err)
		os.Exit(1)
	}

	// Terminal summary
	printSummary(summary)

	// Generate HTML report
	os.MkdirAll(cfg.ReportDir, 0755)
	filename := fmt.Sprintf("security-report-%s.html", time.Now().Format("20060102-150405"))
	reportPath := filepath.Join(cfg.ReportDir, filename)
	latestPath := filepath.Join(cfg.ReportDir, "latest.html")

	if err := report.GenerateHTML(summary, reportPath); err != nil {
		fmt.Fprintf(os.Stderr, "\033[1;31mReport error: %v\033[0m\n", err)
		os.Exit(1)
	}
	os.Remove(latestPath)
	os.Symlink(reportPath, latestPath)

	hostname, _ := os.Hostname()
	fmt.Printf("\033[1;32mHTML report saved:\033[0m  %s\n", reportPath)
	fmt.Printf("\033[0;36mReport URL:\033[0m         http://%s/reports/%s\n", hostname, filename)
	fmt.Printf("\033[0;36mLatest permalink:\033[0m   http://%s/reports/latest.html\n\n", hostname)
}

func printSummary(s *scanner.ScanSummary) {
	affected := s.TotalSites - s.CleanSites

	fmt.Printf("\033[1;36m╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║                 FINAL SUMMARY                ║\n")
	fmt.Printf("╠══════════════════════════════════════════════╣\033[0m\n")
	fmt.Printf(" \033[2mSites scanned: %d  |  Clean: %d  |  Duration: %s\033[0m\n",
		s.TotalSites, s.CleanSites, s.Duration.Round(time.Second))

	if affected > 0 {
		fmt.Printf("\033[1;36m╠══════════════════════════════════════════════╣\033[0m\n")
		for check, domains := range s.FailedChecks {
			fmt.Printf(" \033[1;31m%s:\033[0m\n", check)
			for _, d := range domains {
				fmt.Printf("   \033[0;33m·\033[0m %s\n", d)
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("\n \033[1;32m✔  All %d domain(s) verified — no issues found!\033[0m\n", s.TotalSites)
	}

	fmt.Printf("\033[1;36m╚══════════════════════════════════════════════╝\033[0m\n\n")

	// Per-site detail
	for _, site := range s.Sites {
		if site.HasIssues {
			fmt.Printf("\033[1;31m● %s\033[0m — %d finding(s) in %s\n",
				site.Domain, len(site.Findings), site.ScanDuration.Round(time.Millisecond))
			for _, f := range site.Findings {
				icon := "⚠"
				if f.Severity == scanner.Critical {
					icon = "✘"
				}
				loc := ""
				if f.File != "" {
					loc = f.File + ": "
				}
				fmt.Printf("  %s [%s] %s%s\n", icon, f.Check, loc, f.Detail)
			}
			fmt.Println()
		} else {
			fmt.Printf("\033[1;32m● %s\033[0m — all clear (%s)\n",
				site.Domain, site.ScanDuration.Round(time.Millisecond))
		}
	}
}
