package report

import (
	"fmt"
	"html"
	"os"

	"time"

	"github.com/prasul/wpscan/scanner"
)



// shortPath returns a display-friendly version of a long relative path:
// the last two segments, prefixed with an ellipsis marker if truncated.
// The full path is always preserved in the title attribute by the caller.
func shortPath(rel string) string {
	parts := strings.Split(rel, "/")
	if len(parts) <= 3 {
		return rel
	}
	return ".../" + strings.Join(parts[len(parts)-2:], "/")
}

// writeFindingsTable renders one site's findings grouped by check type.
// Groups over groupCollapseThreshold rows are collapsed behind a native
// <details> disclosure so a single noisy check (e.g. hundreds of files
// touched by one plugin update) doesn't dominate the page.
const groupCollapseThreshold = 8

func writeFindingsTable(f *os.File, findings []scanner.Finding) {
	// Preserve first-seen order of check types.
	var order []string
	groups := make(map[string][]scanner.Finding)
	for _, fnd := range findings {
		if _, ok := groups[fnd.Check]; !ok {
			order = append(order, fnd.Check)
		}
		groups[fnd.Check] = append(groups[fnd.Check], fnd)
	}

	for _, checkName := range order {
		rows := groups[checkName]
		worstBadge, worstLabel := "badge-info", "info"
		for _, r := range rows {
			if r.Severity == scanner.Critical {
				worstBadge, worstLabel = "badge-critical", "critical"
				break
			}
			if r.Severity == scanner.Warning {
				worstBadge, worstLabel = "badge-warning", "warning"
			}
		}

		fmt.Fprintf(f, `<div class="check-group"><div class="check-group-header">
<span class="badge %s">%s</span><span class="check-group-name">%s</span><span class="check-group-count">%d finding(s)</span>
</div><table class="findings-table"><tbody>`, worstBadge, worstLabel, html.EscapeString(checkName), len(rows))

		visible, rest := rows, []scanner.Finding{}
		if len(rows) > groupCollapseThreshold {
			visible, rest = rows[:groupCollapseThreshold], rows[groupCollapseThreshold:]
		}
		for _, r := range visible {
			writeFindingRow(f, r)
		}
		fmt.Fprint(f, `</tbody></table>`)

		if len(rest) > 0 {
			fmt.Fprintf(f, `<details class="finding-more"><summary>Show %d more</summary><table class="findings-table"><tbody>`, len(rest))
			for _, r := range rest {
				writeFindingRow(f, r)
			}
			fmt.Fprint(f, `</tbody></table></details>`)
		}
		fmt.Fprint(f, `</div>`)
	}
}

func writeFindingRow(f *os.File, finding scanner.Finding) {
	badge := "badge-info"
	switch finding.Severity {
	case scanner.Critical:
		badge = "badge-critical"
	case scanner.Warning:
		badge = "badge-warning"
	}
	detail := html.EscapeString(finding.Detail)
	fileCell := ""
	if finding.File != "" {
		fileCell = fmt.Sprintf(`<span class="file-path" title="%s">%s</span>`,
			html.EscapeString(finding.File), html.EscapeString(shortPath(finding.File)))
	}
	fmt.Fprintf(f, `<tr><td style="width:90px"><span class="badge %s">%s</span></td><td class="col-detail">%s<div class="detail-text">%s</div></td></tr>`,
		badge, finding.Severity, fileCell, detail)
}

func GenerateHTML(summary *scanner.ScanSummary, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create report: %w", err)
	}
	defer f.Close()

	affected := summary.TotalSites - summary.CleanSites

	// ── HTML head + CSS
	fmt.Fprint(f, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WordPress Security Report — `+html.EscapeString(summary.ScanDate)+`</title>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--blue-700:#1a73e8;--blue-50:#e8f0fe;--red-700:#c5221f;--red-50:#fce8e6;--yellow-700:#b06000;--yellow-50:#fef7e0;--green-700:#188038;--green-50:#e6f4ea;--grey-900:#202124;--grey-700:#3c4043;--grey-500:#5f6368;--grey-200:#e8eaed;--grey-100:#f1f3f4;--grey-50:#f8f9fa;--white:#fff;--radius:8px;--shadow-sm:0 1px 3px rgba(0,0,0,.10),0 1px 2px rgba(0,0,0,.06)}
body{font-family:'Google Sans','Roboto',Arial,sans-serif;font-size:14px;color:var(--grey-900);background:var(--grey-50);line-height:1.6}
.page-header{background:var(--white);border-bottom:1px solid var(--grey-200);padding:0 40px;position:sticky;top:0;z-index:100}
.header-inner{max-width:1200px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;height:64px}
.header-title{font-size:18px;font-weight:600}.header-sub{font-size:12px;color:var(--grey-500)}
.header-meta{text-align:right;font-size:12px;color:var(--grey-500);line-height:1.9}.header-meta strong{color:var(--grey-700)}
.page-body{max-width:1200px;margin:0 auto;padding:32px 40px 64px}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
.summary-card{background:var(--white);border:1px solid var(--grey-200);border-radius:var(--radius);padding:22px 24px;box-shadow:var(--shadow-sm)}
.sc-value{font-size:36px;font-weight:600;line-height:1;margin-bottom:6px}.sc-label{font-size:11px;color:var(--grey-500);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.sc-blue .sc-value{color:var(--blue-700)}.sc-red .sc-value{color:var(--red-700)}.sc-green .sc-value{color:var(--green-700)}.sc-yellow .sc-value{color:var(--yellow-700)}
.alert-banner{border-radius:var(--radius);padding:14px 20px;margin-bottom:28px;display:flex;align-items:center;gap:12px;font-size:14px;font-weight:500}
.alert-banner.critical{background:var(--red-50);color:var(--red-700);border:1px solid #f5c6c5}
.alert-banner.clean{background:var(--green-50);color:var(--green-700);border:1px solid #a8d5b5}
.section-title{font-size:15px;font-weight:600;margin-bottom:14px;margin-top:32px}
.site-card{background:var(--white);border:1px solid var(--grey-200);border-radius:var(--radius);box-shadow:var(--shadow-sm);margin-bottom:16px;overflow:hidden}
.site-card-header{display:flex;align-items:center;justify-content:space-between;padding:15px 24px;border-bottom:1px solid var(--grey-200);cursor:pointer;user-select:none;transition:background .15s}
.site-card-header:hover{background:var(--grey-50)}
.site-name{font-size:14px;font-weight:600;display:flex;align-items:center;gap:10px}
.site-status-pill{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;padding:3px 11px;border-radius:12px;letter-spacing:.03em}
.pill-clean{background:var(--green-50);color:var(--green-700)}.pill-issues{background:var(--red-50);color:var(--red-700)}
.toggle-icon{font-size:16px;color:var(--grey-500);transition:transform .2s}
.findings-table{width:100%;border-collapse:collapse}
.findings-table th{background:var(--grey-50);padding:9px 18px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--grey-500);border-bottom:1px solid var(--grey-200)}
.findings-table td{padding:10px 18px;border-bottom:1px solid var(--grey-100);vertical-align:top}
.findings-table tr:last-child td{border-bottom:none}.findings-table tr:hover td{background:var(--grey-50)}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap}
.badge-critical{background:var(--red-50);color:var(--red-700)}.badge-warning{background:var(--yellow-50);color:var(--yellow-700)}.badge-info{background:var(--blue-50);color:var(--blue-700)}
.clean-msg{padding:18px 24px;color:var(--green-700);font-size:13px;display:flex;align-items:center;gap:8px}
.col-detail{font-family:'Roboto Mono','Consolas',monospace;font-size:12px;color:var(--grey-700);word-break:break-word}
.check-group{border-top:1px solid var(--grey-200)}
.check-group-header{display:flex;align-items:center;gap:10px;padding:10px 18px;background:var(--grey-50)}
.check-group-name{font-size:12px;font-weight:600;color:var(--grey-900)}
.check-group-count{font-size:11px;color:var(--grey-500);margin-left:auto}
.file-path{display:block;font-weight:600;color:var(--grey-900);margin-bottom:2px;max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help}
.detail-text{color:var(--grey-700)}
.finding-more{border-top:1px solid var(--grey-100)}
.finding-more>summary{padding:8px 18px;font-size:12px;color:var(--blue-700);cursor:pointer;list-style:none;font-weight:500}
.finding-more>summary::-webkit-details-marker{display:none}
.finding-more>summary:before{content:"▸ ";font-size:10px}
.finding-more[open]>summary:before{content:"▾ "}
.page-footer{text-align:center;font-size:12px;color:var(--grey-500);padding:24px 0 0;border-top:1px solid var(--grey-200);margin-top:40px}
@media(max-width:900px){.summary-grid{grid-template-columns:repeat(2,1fr)}.page-body,.page-header{padding-left:20px;padding-right:20px}}
@media print{.site-card-body{display:block!important}.page-header{position:static}}
</style>
</head>
<body>
`)

	// ── Header
	fmt.Fprintf(f, `<header class="page-header"><div class="header-inner">
<div><div class="header-title">WordPress Security Report</div><div class="header-sub">Automated malware &amp; integrity scan</div></div>
<div class="header-meta"><strong>Host:</strong> %s<br><strong>Scan:</strong> %s<br><strong>Duration:</strong> %s · <strong>Sites:</strong> %d</div>
</div></header>
<div class="page-body">
`, html.EscapeString(summary.Hostname), html.EscapeString(summary.ScanDate), summary.Duration.Round(time.Second), summary.TotalSites)

	// ── Alert banner
	if affected > 0 {
		fmt.Fprintf(f, `<div class="alert-banner critical"><strong>%d</strong> of <strong>%d</strong> site(s) have security issues.</div>`, affected, summary.TotalSites)
	} else {
		fmt.Fprintf(f, `<div class="alert-banner clean">All <strong>%d</strong> site(s) passed — no issues detected.</div>`, summary.TotalSites)
	}

	// ── Summary cards
	fmt.Fprintf(f, `<div class="summary-grid">
<div class="summary-card sc-blue"><div class="sc-value">%d</div><div class="sc-label">Sites Scanned</div></div>
<div class="summary-card sc-green"><div class="sc-value">%d</div><div class="sc-label">Fully Clean</div></div>
<div class="summary-card sc-red"><div class="sc-value">%d</div><div class="sc-label">With Issues</div></div>
<div class="summary-card sc-yellow"><div class="sc-value">%d</div><div class="sc-label">Total Findings</div></div>
</div>`, summary.TotalSites, summary.CleanSites, affected, summary.TotalIssues)

	// ── Per-site cards
	fmt.Fprint(f, `<div class="section-title">Per-Site Findings</div>`)
	for _, site := range summary.Sites {
		pill, label := "pill-clean", "All Clear"
		if site.HasIssues {
			pill = "pill-issues"
			label = fmt.Sprintf("%d finding(s)", len(site.Findings))
		}

		fmt.Fprintf(f, `<div class="site-card"><div class="site-card-header">
<span class="site-name">%s</span>
<div style="display:flex;align-items:center;gap:12px">
<span class="site-status-pill %s">%s</span><span class="toggle-icon">▾</span>
</div></div><div class="site-card-body">`, html.EscapeString(site.Domain), pill, label)

		if len(site.Findings) > 0 {
			writeFindingsTable(f, site.Findings)
		} else {
			fmt.Fprint(f, `<div class="clean-msg">✔ All security checks passed — no issues detected.</div>`)
		}
		fmt.Fprint(f, `</div></div>`)
	}

	// ── Footer + JS
	fmt.Fprintf(f, `<div class="page-footer">Envisioned by Prasul · Generated by <strong>wpscan</strong> · %s · %s</div></div>
<script>
document.querySelectorAll('.site-card-header').forEach(function(h){
var b=h.nextElementSibling,i=h.querySelector('.toggle-icon');
if(h.querySelector('.pill-issues')){b.style.display='block';i.style.transform='rotate(180deg)'}else{b.style.display='none'}
h.addEventListener('click',function(){var o=b.style.display!=='none';b.style.display=o?'none':'block';i.style.transform=o?'':'rotate(180deg)'})
});
</script></body></html>`, html.EscapeString(summary.ScanDate), html.EscapeString(summary.Hostname))

	return nil
}
