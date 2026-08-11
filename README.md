# wpscan — WordPress Security Scanner (Go)

Rewrite of `hackchk.sh` in Go with reduced false positives and enhanced detection.

## Key Changes from Bash Version

### Removed (False Positive Reduction)
- **Plugin checksum verification** — `wp plugin verify-checksums` generates excessive false positives for premium/custom plugins. Replaced with:
  - Rogue plugin directory detection (unregistered in WP)
  - Recently modified plugin file flagging (7-day window)
  - Targeted malware pattern scanning within plugin files

### Added (Enhanced Detection)
- **Recently Modified Files** — flags any PHP/JS file modified within 7 days in themes, plugins, mu-plugins, uploads, and core
- **functions.php Hook Injection** — detects wp_head/wp_footer/init hooks that fetch remote content (the #1 WordPress attack vector in 2025-2026)
- **JavaScript Injection Scan** — scans header.php, footer.php, and .js files for obfuscated JS, suspicious external scripts, crypto miners
- **mu-plugins Audit** — scans `wp-content/mu-plugins/` which auto-load and are hidden from admin UI (heavily exploited)
- **Persistent Admin Backdoor** — detects `username_exists`+`wp_create_user` patterns that auto-recreate rogue admins
- **Recently Created Admins** — flags admin accounts created within 7 days
- **Context-Aware PHP Scanning** — skips `wp-admin/`, `wp-includes/`, and known security plugins to eliminate false positives
- **Known Clean Path Exclusions** — security plugins like Wordfence/Sucuri contain malware signatures that trigger false matches

### Pattern Improvements
- PHP patterns require dangerous **combinations** (e.g., `eval` + `base64_decode`) not individual functions
- Base64 blob threshold raised to 300+ chars (was 200) to skip legitimate encoded assets
- JS patterns specifically target the `_0x` obfuscation, `cfasync` bypass, and hidden iframe patterns seen in real 2025 campaigns

## Build

```bash
go build -o wpscan ./cmd/wpscan/
```

## Usage

```bash
# Default scan (Centmin Mod paths) — Critical findings up front, everything
# else in a collapsed "additional context" section underneath
sudo ./wpscan

# Custom paths
sudo ./wpscan -base /var/www/sites -report-dir /var/www/reports

# Verbose + custom recent window
sudo ./wpscan -v -recent-days 14

# Large fleet, only want Critical at all — drop Warning/Info from the
# report entirely instead of just deprioritizing them
sudo ./wpscan -min-severity critical

# Help
./wpscan -h
```

Every finding is tiered by severity, not filtered, by default: Critical findings (a named webshell signature, several corroborating pattern matches on the same file, a plugin/theme version matching a known CVE, PHP dropped fresh into `uploads/`) are shown first and loud, in both the terminal and the HTML report. Warning/Info findings — a single low-confidence pattern match, an odd file touched outside of any update — are still shown, just underneath: collapsed behind a `<details>` in the HTML report, dimmed and after a `— N lower-confidence signal(s), for context —` divider in the terminal. Nothing is thrown away by default, so it's still there to dig into during a hack check without competing with Critical for your attention.

If you'd rather drop Warning/Info from the report entirely (e.g. scanning a large fleet where you only ever act on Critical), set `-min-severity critical` — the summary line will tell you how many findings that hid.

## Checks Performed

| # | Check | Method |
|---|-------|--------|
| 1 | WP Core Checksums | `wp core verify-checksums` |
| 2 | File Placement | PHP in uploads, disguised files, shell scripts, world-writable |
| 3 | Recently Modified | PHP/JS files changed within N days — 3+ files sharing a plugin/theme/core root and mtime collapse into one "X was updated" line instead of one finding per file |
| 4 | File Permissions | wp-config.php, .htaccess directives, uploads execute bit |
| 5 | PHP Malware Scan | High-confidence patterns, confidence-scored, context-aware |
| 6 | Theme Hook Injection | functions.php wp_head C2 callbacks |
| 7 | JS Injection | Obfuscated JS, suspicious externals, miners |
| 8 | mu-plugins Audit | Auto-loaded hidden plugins |
| 9 | Plugin Audit | Rogue dirs, recent mods, malware patterns |
| 10 | Admin Users | Suspicious names, count, recently created |
| 11 | Database Scan | Injected scripts, spam, suspicious options, cron hooks |
| 12 | Known Vulnerabilities | Installed plugin/theme/core versions vs. known-CVE version ranges |

## Confidence Scoring (False Positive Reduction)

Every pattern in `scanner/patterns.go` (and anything you add yourself — see below) carries a `Weight`: **high** (specific enough to act on alone, e.g. a named webshell string), **medium** (a dangerous combination with some legitimate uses), or **low** (a generic building block that's common in legitimate code on its own, e.g. a long base64 blob or a contact form's `mail($_POST[...])`).

Findings are scored per file: one high-weight signal alone is Critical; two-plus corroborating medium/low signals is also Critical; a single medium or a couple of lows is Warning; one lone low signal is Info. Every signal is still scored, counted, and shown — a weak single signal just lands in the collapsed "additional context" section (see Usage above) instead of demanding attention it hasn't earned next to the Critical findings. Each finding's detail line shows `(confidence N, M signal(s))` so you can see why it was scored the way it was.

## Custom Patterns

Copy `cfg/custom_patterns.example.json` to `cfg/custom_patterns.json` (or point `-custom-patterns` at your own path) to add your own regex signatures without touching the Go source. Each entry picks which built-in list it joins (`php`, `functions`, `js`, or `db`) and a `weight` (`low`/`medium`/`high`). Loaded once at the start of every run; a missing file is fine.

## Known Vulnerabilities

Two more optional JSON files feed the "Known Vulnerabilities" check, which compares installed plugin/theme/WP-core versions (via `wp plugin list` / `wp theme list` / `wp core version`) against known-vulnerable version ranges — independent of the pattern scans above, so it catches an unpatched plugin even if nothing on disk looks obfuscated.

- **`cfg/vulnerabilities.json`** — hand-curated. Copy from `cfg/vulnerabilities.example.json` and add anything you've personally confirmed (a 0-day you're tracking, an incident IOC, a plugin you know is unmaintained). Never touched by automation.
- **`cfg/vulnerabilities.wordfence.json`** — machine-managed. Refresh it from the free [Wordfence Intelligence](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) vulnerability feed (no API key required) with:

  ```bash
  ./wpscan vulns update
  ```

  Put it on a weekly cron job so the cache stays current:

  ```cron
  0 3 * * 0  /opt/wpscan/wpscan vulns update
  ```

  This is the only thing in wpscan that makes an outbound network call, and only when this command is run explicitly — never during a normal scan.

  A couple of other free WordPress vulnerability sources worth knowing about, if you'd rather wire in something else later: [WPVulnerability.com](https://www.wpvulnerability.com/api/) (also free/no key, queried per plugin slug, also covers PHP/webserver-stack CVEs) and the [WPScan API](https://wpscan.com/api/) (free tier, 25 requests/day, requires a registered token).

## Output

- Terminal: colored summary with per-site findings
- HTML: interactive report with collapsible site cards (same style as bash version)
