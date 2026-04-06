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
# Default scan (Centmin Mod paths)
sudo ./wpscan

# Custom paths
sudo ./wpscan -base /var/www/sites -report-dir /var/www/reports

# Verbose + custom recent window
sudo ./wpscan -v -recent-days 14

# Help
./wpscan -h
```

## Checks Performed

| # | Check | Method |
|---|-------|--------|
| 1 | WP Core Checksums | `wp core verify-checksums` |
| 2 | File Placement | PHP in uploads, disguised files, shell scripts, world-writable |
| 3 | Recently Modified | PHP/JS files changed within N days |
| 4 | File Permissions | wp-config.php, .htaccess directives, uploads execute bit |
| 5 | PHP Malware Scan | 50+ high-confidence patterns, context-aware |
| 6 | Theme Hook Injection | functions.php wp_head C2 callbacks |
| 7 | JS Injection | Obfuscated JS, suspicious externals, miners |
| 8 | mu-plugins Audit | Auto-loaded hidden plugins |
| 9 | Plugin Audit | Rogue dirs, recent mods, malware patterns |
| 10 | Admin Users | Suspicious names, count, recently created |
| 11 | Database Scan | Injected scripts, spam, suspicious options, cron hooks |

## Output

- Terminal: colored summary with per-site findings
- HTML: interactive report with collapsible site cards (same style as bash version)
