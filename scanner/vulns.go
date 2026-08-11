package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// VulnEntry is a single known-vulnerable version range for a plugin, theme,
// or WordPress core. It's the shared shape used by both the hand-curated
// cfg/vulnerabilities.json and the machine-managed
// cfg/vulnerabilities.wordfence.json cache (see vulns_update.go) — the two
// files are merged in memory at scan time, but never written to each other.
type VulnEntry struct {
	Type          string `json:"type"` // plugin | theme | core
	Slug          string `json:"slug"`
	Name          string `json:"name,omitempty"`
	Title         string `json:"title,omitempty"`
	FromVersion   string `json:"from_version"`   // "*" or "" means no lower bound
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`      // "" means no upper bound
	ToInclusive   bool   `json:"to_inclusive"`
	Severity      string `json:"severity"` // critical | high | warning | medium | info | low
	CVE           string `json:"cve,omitempty"`
	Source        string `json:"source,omitempty"` // "custom" or "wordfence" — set automatically if left blank
	Note          string `json:"note,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
}

// vulnConfigFile is the on-disk wrapper for both vulnerabilities.json and
// vulnerabilities.wordfence.json.
type vulnConfigFile struct {
	Vulnerabilities []VulnEntry `json:"vulnerabilities"`
}

// loadVulnFile reads a vulnerabilities JSON file. A missing file returns
// (nil, nil) — every one of these config files is optional.
func loadVulnFile(path string) ([]VulnEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var f vulnConfigFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for i := range f.Vulnerabilities {
		if f.Vulnerabilities[i].Source == "" {
			f.Vulnerabilities[i].Source = "custom"
		}
		if f.Vulnerabilities[i].FromVersion == "" {
			f.Vulnerabilities[i].FromVersion = "*"
		}
	}

	return f.Vulnerabilities, nil
}

// compareVersions compares two dotted-numeric version strings segment by
// segment (e.g. "1.2.10" > "1.2.9"). A segment that isn't purely numeric
// (e.g. "3-beta") falls back to a plain string comparison for that segment
// only. This covers the vast majority of real-world WordPress plugin/theme
// version strings without pulling in a full semver dependency. Returns -1,
// 0, or 1 like strings.Compare.
func compareVersions(a, b string) int {
	as := strings.Split(strings.TrimSpace(a), ".")
	bs := strings.Split(strings.TrimSpace(b), ".")

	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}

	for i := 0; i < n; i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}

		ai, aErr := strconv.Atoi(av)
		bi, bErr := strconv.Atoi(bv)

		if aErr == nil && bErr == nil {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}

		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}

	return 0
}

// versionInRange reports whether installed falls within [from, to] per the
// given inclusive flags. from == "" or "*" means no lower bound; to == ""
// or "*" means no upper bound.
func versionInRange(installed, from string, fromIncl bool, to string, toIncl bool) bool {
	if from != "" && from != "*" {
		c := compareVersions(installed, from)
		if fromIncl {
			if c < 0 {
				return false
			}
		} else if c <= 0 {
			return false
		}
	}

	if to != "" && to != "*" {
		c := compareVersions(installed, to)
		if toIncl {
			if c > 0 {
				return false
			}
		} else if c >= 0 {
			return false
		}
	}

	return true
}

// severityFromString maps a VulnEntry.Severity label (from either config
// file — "critical"/"high", "warning"/"medium"/"moderate", or anything
// else) onto our Severity type.
func severityFromString(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high":
		return Critical
	case "warning", "medium", "moderate":
		return Warning
	default:
		return Info
	}
}

// CheckKnownVulnerabilities cross-references installed plugin/theme/core
// versions against vulnDB — the merged contents of the hand-curated
// cfg/vulnerabilities.json and the weekly Wordfence Intelligence cache
// (cfg/vulnerabilities.wordfence.json). This is independent of the
// pattern-based malware scans: it flags software that is simply out of
// date against a *known* CVE, whether or not anything on disk looks
// obfuscated or suspicious.
func CheckKnownVulnerabilities(pubDir string, vulnDB []VulnEntry, findings *[]Finding) {
	if len(vulnDB) == 0 {
		return
	}

	bySlug := make(map[string][]VulnEntry, len(vulnDB))
	for _, v := range vulnDB {
		key := v.Type + ":" + strings.ToLower(v.Slug)
		bySlug[key] = append(bySlug[key], v)
	}

	report := func(kind, slug, version string) {
		for _, v := range bySlug[kind+":"+strings.ToLower(slug)] {
			if !versionInRange(version, v.FromVersion, v.FromInclusive, v.ToVersion, v.ToInclusive) {
				continue
			}

			detail := v.Title
			if detail == "" {
				detail = fmt.Sprintf("%s has a known vulnerability affecting <= %s", slug, v.ToVersion)
			}
			if v.CVE != "" {
				detail = fmt.Sprintf("%s [%s]", detail, v.CVE)
			}
			switch {
			case v.Remediation != "":
				detail = fmt.Sprintf("%s — %s", detail, v.Remediation)
			case v.Note != "":
				detail = fmt.Sprintf("%s — %s", detail, v.Note)
			}

			*findings = append(*findings, Finding{
				Severity: severityFromString(v.Severity),
				Check:    "Known Vulnerabilities",
				Detail:   fmt.Sprintf("[%s] %s (installed: %s)", v.Source, detail, version),
				File:     fmt.Sprintf("wp-content/%ss/%s", kind, slug),
			})
		}
	}

	for _, row := range wpCLIRows(pubDir, "plugin", "name,version") {
		report("plugin", row["name"], row["version"])
	}

	for _, row := range wpCLIRows(pubDir, "theme", "name,version") {
		report("theme", row["name"], row["version"])
	}

	if out, err := exec.Command("wp", "--allow-root", "core", "version",
		"--path="+pubDir, "--quiet").Output(); err == nil {
		report("core", "wordpress", strings.TrimSpace(string(out)))
	}
}

// wpCLIRows runs `wp <kind> list --fields=<fields> --format=csv` and parses
// the CSV output into field-name -> value maps, one per row. Returns nil on
// any error (missing wp-cli, no DB connection, etc.) — callers treat that
// the same as "nothing to check", consistent with the rest of the scanner's
// wp-cli-backed checks.
func wpCLIRows(pubDir, kind, fields string) []map[string]string {
	out, err := exec.Command("wp", "--allow-root", kind, "list",
		"--path="+pubDir, "--fields="+fields, "--format=csv", "--quiet").Output()
	if err != nil {
		return nil
	}

	r := csv.NewReader(strings.NewReader(string(out)))
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}

	header := rows[0]
	result := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		m := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(row) {
				m[h] = row[i]
			}
		}
		result = append(result, m)
	}

	return result
}
