package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// wordfenceProductionFeedURL is the Wordfence Intelligence Production
// Vulnerability Feed. It's free, requires no API key/registration, and is
// documented at:
// https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/
//
// This is the only external service wpscan talks to, and only when
// `wpscan vulns update` is run explicitly (never during a normal scan).
const wordfenceProductionFeedURL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"

// wfCVSS mirrors the subset of Wordfence's cvss object we care about.
type wfCVSS struct {
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

// wfAffectedVersion mirrors one entry of Wordfence's software[].affected_versions map.
type wfAffectedVersion struct {
	FromVersion   string `json:"from_version"`
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   bool   `json:"to_inclusive"`
}

// wfSoftware mirrors one entry of Wordfence's software[] array.
type wfSoftware struct {
	Type             string                       `json:"type"` // plugin | theme | core
	Name             string                       `json:"name"`
	Slug             string                       `json:"slug"`
	AffectedVersions map[string]wfAffectedVersion `json:"affected_versions"`
	Remediation      string                       `json:"remediation"`
}

// wfRecord mirrors one top-level record of the Wordfence Production Feed.
// The feed is a JSON object keyed by record UUID; we only care about the
// values, so we decode straight into map[string]wfRecord.
type wfRecord struct {
	ID            string       `json:"id"`
	Title         string       `json:"title"`
	Software      []wfSoftware `json:"software"`
	Informational bool         `json:"informational"`
	CVSS          wfCVSS       `json:"cvss"`
}

// UpdateVulnCache downloads the Wordfence Intelligence Production Feed and
// rewrites it into wpscan's own vulnerabilities cache format at cachePath.
// It never touches vulnerabilities.json (the hand-curated file) — cachePath
// is a separate, fully machine-managed file that's safe to overwrite every
// time this runs. Returns the number of version-range entries written.
//
// Intended to run on a schedule, e.g. weekly via cron:
//
//	0 3 * * 0  /opt/wpscan/wpscan vulns update
func UpdateVulnCache(cachePath string) (int, error) {
	client := &http.Client{Timeout: 5 * time.Minute}

	resp, err := client.Get(wordfenceProductionFeedURL)
	if err != nil {
		return 0, fmt.Errorf("fetch wordfence feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("wordfence feed returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read wordfence feed: %w", err)
	}

	var raw map[string]wfRecord
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, fmt.Errorf("parse wordfence feed: %w", err)
	}

	entries := make([]VulnEntry, 0, len(raw))

	for _, rec := range raw {
		if rec.Informational {
			continue
		}

		for _, sw := range rec.Software {
			if sw.Type != "plugin" && sw.Type != "theme" && sw.Type != "core" {
				continue
			}
			if sw.Slug == "" {
				continue
			}

			sev := rec.CVSS.Rating
			if sev == "" {
				sev = severityLabelFromScore(rec.CVSS.Score)
			}

			for _, rng := range sw.AffectedVersions {
				entries = append(entries, VulnEntry{
					Type:          sw.Type,
					Slug:          sw.Slug,
					Name:          sw.Name,
					Title:         rec.Title,
					FromVersion:   rng.FromVersion,
					FromInclusive: rng.FromInclusive,
					ToVersion:     rng.ToVersion,
					ToInclusive:   rng.ToInclusive,
					Severity:      sev,
					Remediation:   sw.Remediation,
					Source:        "wordfence",
				})
			}
		}
	}

	out, err := json.MarshalIndent(vulnConfigFile{Vulnerabilities: entries}, "", "  ")
	if err != nil {
		return 0, err
	}

	if err := os.WriteFile(cachePath, out, 0600); err != nil {
		return 0, fmt.Errorf("write %s: %w", cachePath, err)
	}

	return len(entries), nil
}

// severityLabelFromScore is a fallback for the rare record missing a CVSS
// rating string, using the same critical/high/medium/low CVSS score bands
// as https://nvd.nist.gov/vuln-metrics/cvss.
func severityLabelFromScore(score float64) string {
	switch {
	case score >= 7:
		return "critical"
	case score >= 4:
		return "warning"
	default:
		return "info"
	}
}
