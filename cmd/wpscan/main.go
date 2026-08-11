package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prasul/wpscan/report"
	"github.com/prasul/wpscan/scanner"
)

// version is stamped at build time via -ldflags "-X main.version=vX.Y.Z"
// by the release workflow. "dev" is what you get on a local `go build`.
var version = "dev"

func main() {
	// `wpscan vulns update` is a separate mode: it doesn't scan anything,
	// it just refreshes the known-vulnerability cache from Wordfence
	// Intelligence. Handled before flag.Parse() since it has its own
	// sub-flags and a leading command word.
	if len(os.Args) > 1 && os.Args[1] == "vulns" {
		runVulnsCommand(os.Args[2:])
		return
	}

	cfg := scanner.DefaultConfig()

	flag.StringVar(&cfg.BaseDir, "base", cfg.BaseDir, "Base directory containing WordPress sites")
	flag.StringVar(&cfg.ReportDir, "report-dir", cfg.ReportDir, "Directory for HTML reports")
	flag.IntVar(&cfg.RecentDays, "recent-days", cfg.RecentDays, "Flag files modified within N days")
	flag.StringVar(&cfg.CustomPatternsPath, "custom-patterns", cfg.CustomPatternsPath, "Path to hand-added pattern signatures (JSON)")
	flag.StringVar(&cfg.VulnConfigPath, "vuln-config", cfg.VulnConfigPath, "Path to hand-added known-vulnerability entries (JSON)")
	flag.StringVar(&cfg.VulnCachePath, "vuln-cache", cfg.VulnCachePath, "Path to the Wordfence vulnerability cache written by `wpscan vulns update`")
	minSeverity := flag.String("min-severity", string(cfg.MinSeverity),
		"Only report findings at or above this severity: critical | warning | info. "+
			"Detection is unaffected either way — this only controls what gets shown.")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.Parse()

	switch strings.ToLower(strings.TrimSpace(*minSeverity)) {
	case "critical":
		cfg.MinSeverity = scanner.Critical
	case "warning":
		cfg.MinSeverity = scanner.Warning
	case "info":
		cfg.MinSeverity = scanner.Info
	default:
		fmt.Fprintf(os.Stderr, "unknown -min-severity %q, using critical\n", *minSeverity)
		cfg.MinSeverity = scanner.Critical
	}

	// Terminal banner
	fmt.Printf("\n\033[1;36m╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║    WordPress Security Scanner %s (Go)    ║\n", version)
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

// runVulnsCommand handles `wpscan vulns update`, which refreshes
// cfg/vulnerabilities.wordfence.json from the free Wordfence Intelligence
// feed. Meant to be run on a schedule (see the -cache flag default and the
// cron example in the README), not from inside a scan.
func runVulnsCommand(args []string) {
	if len(args) == 0 || args[0] != "update" {
		fmt.Println("Usage: wpscan vulns update [-cache path]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("vulns update", flag.ExitOnError)
	cachePath := fs.String("cache", scanner.DefaultConfig().VulnCachePath, "Path to write the Wordfence vulnerability cache")
	fs.Parse(args[1:])

	fmt.Println("Fetching Wordfence Intelligence vulnerability feed (free, no API key)...")

	n, err := scanner.UpdateVulnCache(*cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\033[1;31mError: %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Printf("\033[1;32mSaved %d known-vulnerability entries to %s\033[0m\n", n, *cachePath)
}

// printTieredFindings prints Critical findings first, as a compact table,
// then — if there's anything else — a dimmed "additional context" block of
// Warning/Info findings underneath. Same idea as the HTML report's
// collapsed context section: lead with what's definitely wrong, keep the
// lower-confidence signals available right below instead of hiding them,
// since they're exactly what you want on hand mid hack-check even though
// they don't deserve equal billing with a Critical hit.
func printTieredFindings(findings []scanner.Finding) {
	var critical, context []scanner.Finding
	for _, f := range findings {
		if f.Severity == scanner.Critical {
			critical = append(critical, f)
		} else {
			context = append(context, f)
		}
	}

	printCriticalTable(critical)

	if len(context) == 0 {
		return
	}

	fmt.Printf("  \033[2m— %d lower-confidence signal(s), for context —\033[0m\n", len(context))
	for _, f := range context {
		icon := "ℹ"
		if f.Severity == scanner.Warning {
			icon = "⚠"
		}
		loc := ""
		if f.File != "" {
			loc = f.File + ": "
		}
		fmt.Printf("  \033[2m%s [%s] %s%s\033[0m\n", icon, f.Check, loc, f.Detail)
	}
}

// printCriticalTable renders Critical findings as a compact box-drawn
// table — Path | Check | Detail | Confidence — the same dense,
// single-glance format other scanners use (this mirrors malwatch's own
// `scan` table) instead of one paragraph per finding. Confidence shows "-"
// for deterministic checks (PHP dropped in uploads/, a rogue plugin dir, a
// known-CVE version match) that were never scored in the first place —
// those are just factually true, there's nothing to grade.
func printCriticalTable(findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		path := f.File
		if path == "" {
			path = "-"
		}
		conf := "-"
		if f.Signals > 0 {
			conf = fmt.Sprintf("%d (%d sig)", f.Confidence, f.Signals)
		}
		rows = append(rows, []string{path, f.Check, f.Detail, conf})
	}

	fmt.Println(drawTable([]string{"Path", "Check", "Detail", "Confidence"}, rows))
}

// drawTable renders headers/rows as a Unicode box-drawing table with
// columns sized to their widest cell. No truncation or wrapping — same
// tradeoff malwatch's own table makes — so a long path just makes for a
// wide line rather than losing information.
func drawTable(headers []string, rows [][]string) string {
	n := len(headers)
	widths := make([]int, n)
	for i, h := range headers {
		widths[i] = len([]rune(h))
	}
	for _, r := range rows {
		for i, c := range r {
			if i >= n {
				continue
			}
			if l := len([]rune(c)); l > widths[i] {
				widths[i] = l
			}
		}
	}

	pad := func(s string, w int) string {
		return s + strings.Repeat(" ", w-len([]rune(s)))
	}

	hline := func(left, mid, right, fill string) string {
		var b strings.Builder
		b.WriteString(left)
		for i, w := range widths {
			b.WriteString(strings.Repeat(fill, w+2))
			if i < n-1 {
				b.WriteString(mid)
			}
		}
		b.WriteString(right)
		return b.String()
	}

	writeRow := func(cells []string) string {
		var b strings.Builder
		b.WriteString("║ ")
		for i, w := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			b.WriteString(pad(cell, w))
			if i < n-1 {
				b.WriteString(" │ ")
			}
		}
		b.WriteString(" ║")
		return b.String()
	}

	var b strings.Builder
	b.WriteString(hline("╔", "╤", "╗", "═"))
	b.WriteString("\n")
	b.WriteString(writeRow(headers))
	b.WriteString("\n")
	b.WriteString(hline("╟", "┼", "╢", "━"))
	b.WriteString("\n")
	for _, r := range rows {
		b.WriteString(writeRow(r))
		b.WriteString("\n")
	}
	b.WriteString(hline("╚", "╧", "╝", "═"))
	return b.String()
}

func printSummary(s *scanner.ScanSummary) {
	affected := s.TotalSites - s.CleanSites

	fmt.Printf("\033[1;36m╔══════════════════════════════════════════════╗\n")
	fmt.Printf("║                 FINAL SUMMARY                ║\n")
	fmt.Printf("╠══════════════════════════════════════════════╣\033[0m\n")
	fmt.Printf(" \033[2mSites scanned: %d  |  Clean: %d  |  Duration: %s\033[0m\n",
		s.TotalSites, s.CleanSites, s.Duration.Round(time.Second))
	if s.Hidden > 0 {
		fmt.Printf(" \033[2m%d lower-confidence finding(s) hidden below the report floor — rerun with -min-severity warning (or info) to see them\033[0m\n", s.Hidden)
	}

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

	if len(s.HostFindings) > 0 {
		fmt.Printf("\033[1;35m● Host-level (server cron)\033[0m — %d finding(s)\n", len(s.HostFindings))
		printTieredFindings(s.HostFindings)
		fmt.Println()
	}

	// Per-site detail
	for _, site := range s.Sites {
		if site.HasIssues {
			fmt.Printf("\033[1;31m● %s\033[0m — %d finding(s) in %s\n",
				site.Domain, len(site.Findings), site.ScanDuration.Round(time.Millisecond))
			printTieredFindings(site.Findings)
			fmt.Println()
		} else {
			fmt.Printf("\033[1;32m● %s\033[0m — all clear (%s)\n",
				site.Domain, site.ScanDuration.Round(time.Millisecond))
		}
	}
}
