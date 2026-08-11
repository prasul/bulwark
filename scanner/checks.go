package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// compilePatterns pre-compiles a slice of PatternDef into regexes
func compilePatterns(defs []PatternDef) []*compiledPattern {
	out := make([]*compiledPattern, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			continue
		}
		out = append(out, &compiledPattern{re: re, desc: d.Desc, weight: d.Weight})
	}
	return out
}

type compiledPattern struct {
	re     *regexp.Regexp
	desc   string
	weight int
}

// isKnownCleanPath returns true if the file path is in a known-safe location
func isKnownCleanPath(relPath string) bool {
	for _, prefix := range KnownCleanPHPPaths {
		if strings.Contains(relPath, prefix) {
			return true
		}
	}
	return false
}

// ──────────────────────────────────────────────
// CHECK: Suspicious file placement
// ──────────────────────────────────────────────

func CheckSuspiciousFiles(pubDir string, findings *[]Finding) {
	// PHP in uploads (always malicious)
	uploadsDir := filepath.Join(pubDir, "wp-content", "uploads")
	filepath.WalkDir(uploadsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".php" || ext == ".php5" || ext == ".phtml" || ext == ".phar" {
			rel, _ := filepath.Rel(pubDir, path)
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "File Placement",
				Detail:   "PHP file inside uploads directory (must not exist)",
				File:     rel,
			})
		}
		return nil
	})

	// Disguised PHP files
	wcDir := filepath.Join(pubDir, "wp-content")
	disguisedExts := map[string]bool{
		".php.jpg": true, ".php.png": true, ".php.gif": true,
		".php.js": true, ".php5": true, ".phtml": true, ".phar": true,
	}
	filepath.WalkDir(wcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		for ext := range disguisedExts {
			if strings.HasSuffix(strings.ToLower(name), ext) &&
				!strings.Contains(path, ".git") {
				rel, _ := filepath.Rel(pubDir, path)
				*findings = append(*findings, Finding{
					Severity: Critical,
					Check:    "File Placement",
					Detail:   "PHP file disguised as another file type",
					File:     rel,
				})
				break
			}
		}
		return nil
	})

	// Shell scripts in webroot
	scriptExts := map[string]bool{".sh": true, ".py": true, ".pl": true, ".cgi": true}
	depth := 0
	filepath.WalkDir(pubDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(pubDir, path)
			depth = strings.Count(rel, string(os.PathSeparator))
			if depth > 3 {
				return fs.SkipDir
			}
			if strings.Contains(path, ".git") {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if scriptExts[ext] {
			rel, _ := filepath.Rel(pubDir, path)
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "File Placement",
				Detail:   "Shell/script file found in webroot",
				File:     rel,
			})
		}
		return nil
	})

	// World-writable PHP files
	filepath.WalkDir(pubDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.Contains(path, ".git") {
			return nil
		}
		if strings.ToLower(filepath.Ext(d.Name())) != ".php" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Mode().Perm()&0002 != 0 { // world-writable
			rel, _ := filepath.Rel(pubDir, path)
			*findings = append(*findings, Finding{
				Severity: Warning,
				Check:    "File Placement",
				Detail:   fmt.Sprintf("World-writable PHP file (mode %04o)", info.Mode().Perm()),
				File:     rel,
			})
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: Recently modified files (7 days)
// ──────────────────────────────────────────────

func CheckRecentlyModified(pubDir string, recentDays int, findings *[]Finding) {
	cutoff := time.Now().AddDate(0, 0, -recentDays)
	phpExts := map[string]bool{".php": true, ".php5": true, ".phtml": true, ".phar": true, ".js": true}

	// Track which directories are interesting
	suspiciousDirs := []string{
		filepath.Join(pubDir, "wp-content", "themes"),
		filepath.Join(pubDir, "wp-content", "plugins"),
		filepath.Join(pubDir, "wp-content", "mu-plugins"),
		filepath.Join(pubDir, "wp-content", "uploads"),
	}

	// Collect raw hits first so we can spot update bursts before emitting
	// findings — a single `wp plugin update` (or a core auto-update)
	// touches a batch of files with an identical mtime, and reporting each
	// one individually is noise, not signal. Root-level core files
	// (wp-login.php etc.) join the same pipeline as plugin/theme files so a
	// core update collapses the same way.
	type hit struct {
		rel      string
		mtime    time.Time
		severity Severity
	}
	var hits []hit

	entries, _ := os.ReadDir(pubDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".php") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			hits = append(hits, hit{rel: name, mtime: info.ModTime(), severity: Warning})
		}
	}

	for _, dir := range suspiciousDirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if !phpExts[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.ModTime().After(cutoff) {
				rel, _ := filepath.Rel(pubDir, path)
				severity := Warning
				// PHP in uploads that's also recent = definitely malicious
				if strings.Contains(path, "uploads") && ext != ".js" {
					severity = Critical
				}
				hits = append(hits, hit{rel: rel, mtime: info.ModTime(), severity: severity})
			}
			return nil
		})
	}

	// Group by (plugin/theme/mu-plugin/core root, mtime rounded to the
	// minute). Real updates — wp-cli, WP core auto-update, a human running
	// a deploy — touch a batch of files that all land with the same
	// to-the-minute mtime; a targeted backdoor drop essentially never does.
	// 3+ files sharing both collapse into a single "X was updated" line;
	// PHP files in uploads never collapse since that combination is always
	// Critical regardless of how it got there.
	const burstThreshold = 3

	type groupKey struct {
		root  string
		stamp string
	}
	groups := make(map[groupKey][]hit)
	for _, h := range hits {
		if h.severity == Critical {
			continue // never collapse the high-confidence uploads/PHP case
		}
		key := groupKey{root: burstRoot(h.rel), stamp: h.mtime.Format("2006-01-02 15:04")}
		groups[key] = append(groups[key], h)
	}

	collapsed := make(map[string]bool)
	for key, group := range groups {
		if len(group) < burstThreshold {
			continue
		}
		for _, h := range group {
			collapsed[h.rel] = true
		}
		*findings = append(*findings, Finding{
			Severity: Info,
			Check:    "Recently Modified",
			Detail:   fmt.Sprintf("%s (%d files, mtime %s)", updateLabel(key.root), len(group), key.stamp),
			File:     key.root,
		})
	}

	for _, h := range hits {
		if collapsed[h.rel] {
			continue
		}
		*findings = append(*findings, Finding{
			Severity: h.severity,
			Check:    "Recently Modified",
			Detail:   fmt.Sprintf("File modified within %d days (mtime: %s)", recentDays, h.mtime.Format("2006-01-02 15:04")),
			File:     h.rel,
		})
	}
}

// burstRoot returns the plugin/theme/mu-plugin directory a relative path
// belongs to (e.g. "wp-content/plugins/google-site-kit"), a synthetic
// "wordpress-core" root for root-level core files (wp-login.php, etc.) so
// they can burst-collapse together too, or the path itself as a fallback.
// Used to group mtime bursts.
func burstRoot(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) >= 3 && parts[0] == "wp-content" {
		return strings.Join(parts[:3], "/")
	}
	if len(parts) == 1 {
		return "wordpress-core"
	}
	return rel
}

// updateLabel turns a burstRoot() value into a short, human sentence for
// the collapsed "Recently Modified" finding — e.g. "google-site-kit plugin
// was updated" instead of a raw path and a file count.
func updateLabel(root string) string {
	if root == "wordpress-core" {
		return "WordPress core files were updated"
	}

	parts := strings.Split(root, "/")
	if len(parts) == 3 && parts[0] == "wp-content" {
		kind := map[string]string{
			"plugins":    "plugin",
			"themes":     "theme",
			"mu-plugins": "mu-plugin",
			"uploads":    "files in uploads",
		}[parts[1]]
		if kind == "" {
			return root + " was updated"
		}
		return fmt.Sprintf("%s %s was updated", parts[2], kind)
	}

	return root + " was updated"
}

// ──────────────────────────────────────────────
// CHECK: PHP malware scan (context-aware)
// ──────────────────────────────────────────────

func CheckPHPMalware(pubDir string, findings *[]Finding) {
	patterns := compilePatterns(PHPMalwarePatterns)
	seen := make(map[string]bool)
	phpExts := map[string]bool{".php": true, ".php5": true, ".phtml": true}

	filepath.WalkDir(pubDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Skip directories
		for _, skip := range []string{".git", "node_modules", ".infected"} {
			if strings.Contains(path, skip) {
				return nil
			}
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !phpExts[ext] {
			return nil
		}
		rel, _ := filepath.Rel(pubDir, path)

		// Skip known clean paths (wp-admin, wp-includes, security plugins)
		if isKnownCleanPath(rel) {
			return nil
		}

		if seen[rel] {
			return nil
		}

		matches := scanFileForPatterns(path, patterns)
		if len(matches) > 0 {
			seen[rel] = true
			score, severity := scoreMatches(matches)
			ctx := make([]string, 0, 3)
			for i, m := range matches {
				if i >= 3 {
					break
				}
				ctx = append(ctx, fmt.Sprintf("L%d: %s", m.line, m.desc))
			}
			*findings = append(*findings, Finding{
				Severity:   severity,
				Check:      "PHP Malware Scan",
				Detail:     fmt.Sprintf("%s (confidence %d, %d signal(s))", strings.Join(ctx, " | "), score, signalCount(matches)),
				File:       rel,
				Line:       matches[0].line,
				Confidence: score,
				Signals:    signalCount(matches),
			})
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: functions.php / theme hook injection
// ──────────────────────────────────────────────

func CheckFunctionsInjection(pubDir string, findings *[]Finding) {
	patterns := compilePatterns(FunctionsPHPPatterns)
	themesDir := filepath.Join(pubDir, "wp-content", "themes")

	filepath.WalkDir(themesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		// Check functions.php, index.php, header.php, footer.php in themes
		interesting := name == "functions.php" || name == "index.php" ||
			name == "header.php" || name == "footer.php"
		if !interesting {
			return nil
		}

		rel, _ := filepath.Rel(pubDir, path)
		matches := scanFileForPatterns(path, patterns)
		if len(matches) == 0 {
			return nil
		}
		score, severity := scoreMatches(matches)
		ctx := make([]string, 0, 3)
		for i, m := range matches {
			if i >= 3 {
				break
			}
			ctx = append(ctx, fmt.Sprintf("L%d: %s — %s", m.line, m.desc, m.context))
		}
		*findings = append(*findings, Finding{
			Severity:   severity,
			Check:      "Theme Hook Injection",
			Detail:     fmt.Sprintf("%s (confidence %d, %d signal(s))", strings.Join(ctx, " | "), score, signalCount(matches)),
			File:       rel,
			Line:       matches[0].line,
			Confidence: score,
			Signals:    signalCount(matches),
		})
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: JavaScript injection in theme files
// ──────────────────────────────────────────────

func CheckJSInjection(pubDir string, findings *[]Finding) {
	patterns := compilePatterns(JSInjectionPatterns)

	// Scan theme PHP files (header.php, footer.php) and .js files
	themesDir := filepath.Join(pubDir, "wp-content", "themes")
	jsExts := map[string]bool{".js": true, ".php": true}

	filepath.WalkDir(themesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !jsExts[ext] {
			return nil
		}
		// For PHP files, only check header/footer
		if ext == ".php" {
			name := strings.ToLower(d.Name())
			if name != "header.php" && name != "footer.php" {
				return nil
			}
		}

		rel, _ := filepath.Rel(pubDir, path)
		matches := scanFileForPatterns(path, patterns)
		addJSFinding(findings, rel, matches)
		return nil
	})

	// Also scan .js files in the root public dir (wp-config.js injection pattern)
	entries, _ := os.ReadDir(pubDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		path := filepath.Join(pubDir, e.Name())
		matches := scanFileForPatterns(path, patterns)
		addJSFinding(findings, e.Name(), matches)
	}
}

// addJSFinding aggregates a file's pattern matches into one confidence-scored
// finding instead of emitting one Critical finding per matched line — a
// script that only trips one Low-weight signal (e.g. an unrecognized CDN
// domain) shouldn't carry the same severity as one tripping several.
func addJSFinding(findings *[]Finding, rel string, matches []matchResult) {
	if len(matches) == 0 {
		return
	}
	score, severity := scoreMatches(matches)
	ctx := make([]string, 0, 3)
	for i, m := range matches {
		if i >= 3 {
			break
		}
		ctx = append(ctx, fmt.Sprintf("L%d: %s — %s", m.line, m.desc, m.context))
	}
	*findings = append(*findings, Finding{
		Severity:   severity,
		Check:      "JS Injection",
		Detail:     fmt.Sprintf("%s (confidence %d, %d signal(s))", strings.Join(ctx, " | "), score, signalCount(matches)),
		File:       rel,
		Line:       matches[0].line,
		Confidence: score,
		Signals:    signalCount(matches),
	})
}

// ──────────────────────────────────────────────
// CHECK: mu-plugins directory (must-use plugins)
// ──────────────────────────────────────────────

func CheckMuPlugins(pubDir string, findings *[]Finding) {
	muDir := filepath.Join(pubDir, "wp-content", "mu-plugins")
	if _, err := os.Stat(muDir); os.IsNotExist(err) {
		return
	}

	patterns := compilePatterns(PHPMalwarePatterns)
	jsPatterns := compilePatterns(JSInjectionPatterns)

	filepath.WalkDir(muDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(pubDir, path)

		// Any PHP file in mu-plugins should be flagged for review
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".php" || ext == ".php5" || ext == ".phtml" {
			*findings = append(*findings, Finding{
				Severity: Warning,
				Check:    "mu-plugins Audit",
				Detail:   "Must-use plugin found — verify legitimacy (auto-loaded, hidden from admin)",
				File:     rel,
			})

			// Scan content for malware
			allPatterns := append(patterns, jsPatterns...)
			matches := scanFileForPatterns(path, allPatterns)
			if len(matches) > 0 {
				score, severity := scoreMatches(matches)
				ctx := make([]string, 0, 3)
				for i, m := range matches {
					if i >= 3 {
						break
					}
					ctx = append(ctx, fmt.Sprintf("L%d: %s", m.line, m.desc))
				}
				*findings = append(*findings, Finding{
					Severity:   severity,
					Check:      "mu-plugins Malware",
					Detail:     fmt.Sprintf("%s (confidence %d, %d signal(s))", strings.Join(ctx, " | "), score, signalCount(matches)),
					Confidence: score,
					Signals:    signalCount(matches),
					File:     rel,
					Line:     matches[0].line,
				})
			}
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: File permissions
// ──────────────────────────────────────────────

func CheckPermissions(pubDir string, findings *[]Finding) {
	// wp-config.php
	wpConfig := filepath.Join(pubDir, "wp-config.php")
	if info, err := os.Stat(wpConfig); err == nil {
		perm := info.Mode().Perm()
		if perm&0007 > 0 { // world-readable/writable
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "File Permissions",
				Detail:   fmt.Sprintf("wp-config.php is world-accessible (mode %04o) — should be 400 or 440", perm),
				File:     "wp-config.php",
			})
		}
	}

	// .htaccess PHP directives
	htaccess := filepath.Join(pubDir, ".htaccess")
	if _, err := os.Stat(htaccess); err == nil {
		data, _ := os.ReadFile(htaccess)
		content := string(data)
		htPatterns := []string{
			`(?i)AddType.*application/x-httpd-php`,
			`(?i)php_value`,
			`(?i)php_flag`,
			`(?i)auto_prepend_file`,
			`(?i)auto_append_file`,
		}
		for _, p := range htPatterns {
			re, _ := regexp.Compile(p)
			if re.MatchString(content) {
				*findings = append(*findings, Finding{
					Severity: Critical,
					Check:    "File Permissions",
					Detail:   "htaccess contains PHP execution directives — possible injection vector",
					File:     ".htaccess",
				})
				break
			}
		}
	}

	// uploads directory execute bit
	uploadsDir := filepath.Join(pubDir, "wp-content", "uploads")
	if info, err := os.Stat(uploadsDir); err == nil {
		perm := info.Mode().Perm()
		if perm&0111 != 0 { // any execute bit
			*findings = append(*findings, Finding{
				Severity: Warning,
				Check:    "File Permissions",
				Detail:   fmt.Sprintf("wp-content/uploads has execute bit set (%04o)", perm),
				File:     "wp-content/uploads/",
			})
		}
	}
}

// ──────────────────────────────────────────────
// CHECK: WP Core checksums (via wp-cli)
// ──────────────────────────────────────────────

func CheckCoreChecksums(pubDir string, findings *[]Finding) {
	cmd := exec.Command("wp", "--allow-root", "core", "verify-checksums",
		"--path="+pubDir, "--quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		*findings = append(*findings, Finding{
			Severity: Critical,
			Check:    "Core Checksums",
			Detail:   fmt.Sprintf("WP core checksum verification failed: %s", strings.TrimSpace(string(output))),
		})
	}
}

// ──────────────────────────────────────────────
// CHECK: Admin users (via wp-cli)
// ──────────────────────────────────────────────

func CheckAdminUsers(pubDir string, findings *[]Finding) {
	// Count admins
	cmd := exec.Command("wp", "--allow-root", "user", "list",
		"--path="+pubDir, "--role=administrator", "--format=count", "--quiet")
	out, err := cmd.Output()
	if err != nil {
		*findings = append(*findings, Finding{
			Severity: Info,
			Check:    "Admin Users",
			Detail:   "Could not retrieve user list — manual check required",
		})
		return
	}
	count := strings.TrimSpace(string(out))

	// Suspicious usernames
	cmd = exec.Command("wp", "--allow-root", "user", "list",
		"--path="+pubDir, "--fields=user_login,user_email", "--format=csv", "--quiet")
	out, _ = cmd.Output()
	suspiciousRe := regexp.MustCompile(`(?i)(admin\d+|support_\w+|wordpress_\w+|wp_\w+|test_admin|backdoor|shell|hack|help)`)
	for _, line := range strings.Split(string(out), "\n") {
		if suspiciousRe.MatchString(line) && !strings.HasPrefix(line, "user_login") {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Admin Users",
				Detail:   fmt.Sprintf("Suspicious administrator: %s (total admins: %s)", strings.TrimSpace(line), count),
			})
		}
	}

	// Check for recently created admins (last 7 days)
	cmd = exec.Command("wp", "--allow-root", "user", "list",
		"--path="+pubDir, "--role=administrator",
		"--fields=user_login,user_email,user_registered", "--format=csv", "--quiet")
	out, _ = cmd.Output()
	cutoff := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "user_login") || line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 3 {
			regDate := strings.TrimSpace(parts[2])
			if regDate >= cutoff {
				*findings = append(*findings, Finding{
					Severity: Critical,
					Check:    "Admin Users",
					Detail:   fmt.Sprintf("Admin account created within 7 days: %s (registered %s)", parts[0], regDate),
				})
			}
		}
	}
}

// ──────────────────────────────────────────────
// CHECK: Database malware (via wp-cli)
// ──────────────────────────────────────────────

func CheckDatabase(pubDir string, findings *[]Finding) {
	// Verify DB connection
	cmd := exec.Command("wp", "--allow-root", "db", "check",
		"--path="+pubDir, "--quiet")
	if err := cmd.Run(); err != nil {
		*findings = append(*findings, Finding{
			Severity: Info,
			Check:    "Database Scan",
			Detail:   "Cannot connect to database — scan skipped",
		})
		return
	}

	for _, pd := range DBMalwarePatterns {
		cmd := exec.Command("wp", "--allow-root", "db", "search", pd.Pattern,
			"--path="+pubDir, "--regex", "--stats", "--quiet")
		out, _ := cmd.CombinedOutput()
		outStr := string(out)
		if strings.Contains(outStr, "match") && !strings.Contains(outStr, "0 matches") {
			*findings = append(*findings, Finding{
				Severity:   severityForWeight(pd.Weight),
				Check:      "Database Scan",
				Detail:     fmt.Sprintf("Suspicious DB content: %s", pd.Desc),
				Confidence: pd.Weight,
				Signals:    1,
			})
		}
	}

	// Check wp_options for suspicious keys
	cmd = exec.Command("wp", "--allow-root", "option", "list",
		"--path="+pubDir, "--format=csv", "--quiet")
	out, _ := cmd.Output()
	for _, key := range SuspiciousWPOptionKeys {
		if strings.Contains(string(out), key) {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Database Scan",
				Detail:   fmt.Sprintf("Suspicious wp_options key found: %s", key),
			})
		}
	}

	// Non-standard cron hooks
	cmd = exec.Command("wp", "--allow-root", "cron", "event", "list",
		"--path="+pubDir, "--format=csv", "--fields=hook,next_run", "--quiet")
	out, _ = cmd.Output()
	knownHooks := map[string]bool{
		"hook": true, "wp_scheduled_delete": true, "wp_update_themes": true,
		"wp_update_plugins": true, "wp_version_check": true,
		"wp_scheduled_auto_draft_delete": true, "delete_expired_transients": true,
		"recovery_mode_clean_expired_keys": true, "wp_privacy_delete_old_export_files": true,
		"wp_site_health_scheduled_check": true, "wp_https_detection": true,
		"wp_update_comment_type_batch": true,
	}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			hook := strings.TrimSpace(parts[0])
			if hook != "" && !knownHooks[hook] {
				*findings = append(*findings, Finding{
					Severity: Warning,
					Check:    "Database Scan",
					Detail:   fmt.Sprintf("Non-standard WP cron hook — verify: %s", hook),
				})
			}
		}
	}
}

// ──────────────────────────────────────────────
// CHECK: Plugin audit (NO checksums — just rogue dirs + recent mods)
// ──────────────────────────────────────────────

func CheckPlugins(pubDir string, recentDays int, findings *[]Finding) {
	pluginPath := filepath.Join(pubDir, "wp-content", "plugins")
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return
	}

	// Get registered plugin list
	cmd := exec.Command("wp", "--allow-root", "--skip-plugins", "plugin", "list",
		"--path="+pubDir, "--format=csv", "--fields=name,status,version", "--quiet")
	out, err := cmd.Output()
	if err != nil {
		*findings = append(*findings, Finding{
			Severity: Info,
			Check:    "Plugin Audit",
			Detail:   "Could not retrieve plugin list via WP-CLI",
		})
		return
	}

	registered := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 1 && parts[0] != "name" {
			registered[parts[0]] = true
		}
	}

	// Detect unregistered plugin directories
	entries, _ := os.ReadDir(pluginPath)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !registered[e.Name()] {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Plugin Audit",
				Detail:   fmt.Sprintf("Plugin directory not registered in WordPress (rogue install): %s", e.Name()),
				File:     filepath.Join("wp-content/plugins", e.Name()),
			})
		}
	}

	// Scan plugin PHP files for malware (instead of checksums)
	patterns := compilePatterns(PHPMalwarePatterns)
	cutoff := time.Now().AddDate(0, 0, -recentDays)

	filepath.WalkDir(pluginPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".php" && ext != ".php5" && ext != ".phtml" {
			return nil
		}
		rel, _ := filepath.Rel(pubDir, path)

		// Check recently modified plugin files
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(cutoff) {
			*findings = append(*findings, Finding{
				Severity: Warning,
				Check:    "Plugin Audit",
				Detail:   fmt.Sprintf("Plugin file modified within %d days (mtime: %s)", recentDays, info.ModTime().Format("2006-01-02 15:04")),
				File:     rel,
			})
		}

		// Malware pattern scan
		matches := scanFileForPatterns(path, patterns)
		if len(matches) > 0 {
			score, severity := scoreMatches(matches)
			ctx := make([]string, 0, 3)
			for i, m := range matches {
				if i >= 3 {
					break
				}
				ctx = append(ctx, fmt.Sprintf("L%d: %s", m.line, m.desc))
			}
			*findings = append(*findings, Finding{
				Severity:   severity,
				Check:      "Plugin Malware",
				Detail:     fmt.Sprintf("%s (confidence %d, %d signal(s))", strings.Join(ctx, " | "), score, signalCount(matches)),
				File:       rel,
				Line:       matches[0].line,
				Confidence: score,
				Signals:    signalCount(matches),
			})
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: PHP comment-hidden backdoors (<?php /*- ... )
// ──────────────────────────────────────────────

func CheckCommentBackdoors(pubDir string, findings *[]Finding) {
	patterns := compilePatterns(PHPCommentBackdoorPatterns)
	phpExts := map[string]bool{".php": true, ".php5": true, ".phtml": true}

	filepath.WalkDir(pubDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		for _, skip := range []string{".git", "node_modules", ".infected"} {
			if strings.Contains(path, skip) {
				return nil
			}
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !phpExts[ext] {
			return nil
		}
		rel, _ := filepath.Rel(pubDir, path)
		if isKnownCleanPath(rel) {
			return nil
		}
		matches := scanFileForPatterns(path, patterns)
		for _, m := range matches {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "PHP Malware Scan",
				Detail:   m.desc,
				File:     rel,
				Line:     m.line,
			})
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// CHECK: High-risk snippet plugins + DB-stored snippet payloads
// ──────────────────────────────────────────────

func CheckHighRiskPluginsAndSnippets(pubDir string, findings *[]Finding) {
	// 1. Installed/active snippet-execution plugins — flagged for review,
	// not auto-critical, since these are legitimately used too.
	for _, slug := range HighRiskSnippetPlugins {
		cmd := exec.Command("wp", "--allow-root", "plugin", "is-installed", slug, "--path="+pubDir)
		if err := cmd.Run(); err != nil {
			continue // not installed
		}
		out, _ := exec.Command("wp", "--allow-root", "plugin", "status", slug,
			"--path="+pubDir, "--format=csv", "--quiet").Output()
		status := "unknown"
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			parts := strings.Split(lines[1], ",")
			if len(parts) >= 2 {
				status = parts[1]
			}
		}
		*findings = append(*findings, Finding{
			Severity: Warning,
			Check:    "Snippet Audit",
			Detail:   fmt.Sprintf("High-risk snippet/file-manager plugin installed (status: %s) — verify who has access", status),
			File:     "wp-content/plugins/" + slug,
		})
	}

	// 2. Raw snippet payloads sitting in wp_options — this is where the
	// actual injectable PHP lives regardless of which plugin wrote it.
	prefixOut, err := exec.Command("wp", "--allow-root", "config", "get", "table_prefix",
		"--path="+pubDir, "--quiet").Output()
	if err != nil {
		return
	}
	prefix := strings.TrimSpace(string(prefixOut))
	if prefix == "" {
		prefix = "wp_"
	}
	optionsTable := prefix + "options"

	inClause := "'" + strings.Join(SnippetOptionKeys, "','") + "'"
	query := fmt.Sprintf("SELECT option_name FROM %s WHERE option_name IN (%s)", optionsTable, inClause)
	out, _ := exec.Command("wp", "--allow-root", "db", "query", query,
		"--path="+pubDir, "--skip-column-names", "--quiet").Output()

	for _, key := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		*findings = append(*findings, Finding{
			Severity: Warning,
			Check:    "Snippet Audit",
			Detail: fmt.Sprintf(
				"Snippet payload stored in wp_options (%s) — inspect with: wp eval 'global $wpdb; echo $wpdb->get_var(\"SELECT option_value FROM %s WHERE option_name = \\\"%s\\\"\");' — remove with: wp db query \"DELETE FROM %s WHERE option_name='%s'\"",
				key, optionsTable, key, optionsTable, key),
		})
	}
}

// ──────────────────────────────────────────────
// CHECK: PHP payloads embedded inside real image files
// ──────────────────────────────────────────────

// imageMarker is a byte sequence with no business appearing inside a
// genuine image, plus how much confidence weight it carries depending on
// *where* it's found:
//
//   - inTrailer: found after the image's own legitimate end-of-file marker
//     (JPEG EOI, PNG IEND, GIF trailer). Genuine images have nothing
//     meaningful back there — this is the actual polyglot-file signature
//     (e.g. valid JPEG bytes followed by an appended PHP payload), so it's
//     weighted high.
//   - inBody: found somewhere before that point. This is much weaker on
//     its own — EXIF/IPTC/XMP metadata and ICC color profiles routinely
//     carry arbitrary binary or tool-generated text, and a short sequence
//     like "<?=" can turn up there by pure coincidence in a large enough
//     file. Weighted low unless corroborated by another marker.
type imageMarker struct {
	bytes     []byte
	inBody    int
	inTrailer int
}

var imageMarkers = []imageMarker{
	{bytes: []byte("<?php"), inBody: WeightMedium, inTrailer: WeightHigh},
	{bytes: []byte("<?="), inBody: WeightLow, inTrailer: WeightMedium},
	{bytes: []byte("eval("), inBody: WeightMedium, inTrailer: WeightHigh},
	{bytes: []byte("base64_decode("), inBody: WeightMedium, inTrailer: WeightHigh},
}

// imageMagic maps a recognized extension to the real magic-byte header a
// genuine file of that type starts with (GIF is checked separately since
// it has two valid variants). A file can lie about its extension; it
// can't lie about its own format's magic bytes without literally not
// being that format — a mismatch here is a far more specific signal than
// "some PHP-looking text appears somewhere in this file" ever is alone.
var imageMagic = map[string][]byte{
	".jpg":  {0xFF, 0xD8, 0xFF},
	".jpeg": {0xFF, 0xD8, 0xFF},
	".png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
	".ico":  {0x00, 0x00, 0x01, 0x00},
}

const maxImageScanSize = 20 * 1024 * 1024 // skip anything absurdly large

func CheckImageEmbeddedPHP(pubDir string, findings *[]Finding) {
	uploadsDir := filepath.Join(pubDir, "wp-content", "uploads")
	imageExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true,
	}

	filepath.WalkDir(uploadsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !imageExts[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxImageScanSize || info.Size() == 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(pubDir, path)

		if !hasImageMagic(ext, data) {
			// Extension says image, magic bytes say otherwise — this is
			// structurally not the file type it claims to be, independent
			// of whatever is or isn't found inside it. Always Critical:
			// there's no ambiguity to grade here, unlike a byte-string
			// match.
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Image Payload Scan",
				Detail:   fmt.Sprintf("File has a %s extension but does not have a real %s header — not actually an image", ext, strings.ToUpper(strings.TrimPrefix(ext, "."))),
				File:     rel,
			})
			return nil
		}

		trailerAt := imageTrailerEnd(ext, data)

		score := 0
		var hits []string
		for _, m := range imageMarkers {
			idx := bytes.Index(data, m.bytes)
			if idx < 0 {
				continue
			}
			if trailerAt >= 0 && idx >= trailerAt {
				score += m.inTrailer
				hits = append(hits, fmt.Sprintf("%s (after end-of-file marker)", string(m.bytes)))
			} else {
				score += m.inBody
				hits = append(hits, string(m.bytes))
			}
		}

		if score == 0 {
			return nil
		}

		*findings = append(*findings, Finding{
			Severity:   severityForScore(score),
			Check:      "Image Payload Scan",
			Detail:     fmt.Sprintf("Possible PHP payload inside image: %s (confidence %d)", strings.Join(hits, ", "), score),
			File:       rel,
			Confidence: score,
			Signals:    len(hits),
		})
		return nil
	})
}

// hasImageMagic reports whether data actually starts with the magic bytes
// for ext, rather than trusting the filename.
func hasImageMagic(ext string, data []byte) bool {
	if ext == ".gif" {
		return bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))
	}
	magic, ok := imageMagic[ext]
	if !ok {
		return true // unrecognized extension — shouldn't happen given imageExts, nothing to check
	}
	return bytes.HasPrefix(data, magic)
}

// imageTrailerEnd returns the byte offset right after the image's own
// legitimate end-of-file marker (the *last* occurrence, in case
// entropy-coded scan data coincidentally contains an earlier lookalike),
// or -1 if none is found — e.g. a truncated file — in which case every
// marker is treated as "in body" rather than assumed to be past a trailer
// that may not actually exist.
func imageTrailerEnd(ext string, data []byte) int {
	switch ext {
	case ".jpg", ".jpeg":
		if i := bytes.LastIndex(data, []byte{0xFF, 0xD9}); i >= 0 {
			return i + 2
		}
	case ".png":
		if i := bytes.LastIndex(data, []byte("IEND")); i >= 0 {
			if end := i + 4 + 4; end <= len(data) { // chunk type + CRC32
				return end
			}
		}
	case ".gif":
		if i := bytes.LastIndexByte(data, 0x3B); i >= 0 {
			return i + 1
		}
	}
	return -1
}

// ──────────────────────────────────────────────
// CHECK: Server-level cron (host, not per-site)
// ──────────────────────────────────────────────
// wp cron event list only sees WordPress's own scheduler. A backdoor that
// re-adds itself via the OS crontab survives a full WP reinstall and never
// shows up there. This reads the actual system cron sources instead.

var suspiciousCronPatterns = []PatternDef{
	{Pattern: `curl[^|]*\|\s*(ba)?sh`, Desc: "curl piped directly into a shell"},
	{Pattern: `wget[^|]*\|\s*(ba)?sh`, Desc: "wget piped directly into a shell"},
	{Pattern: `base64\s+-d`, Desc: "base64 decode in cron entry"},
	{Pattern: `php\s+-r\s+["']`, Desc: "inline PHP one-liner (php -r)"},
	{Pattern: `/tmp/[\w.\-]+\.(sh|php|py)`, Desc: "executable staged in /tmp"},
	{Pattern: `(?i)\bnc\s+-e\b`, Desc: "netcat reverse-shell flag (-e)"},
}

func CheckServerCron(findings *[]Finding) {
	patterns := compilePatterns(suspiciousCronPatterns)
	seen := make(map[string]bool)

	addEntry := func(source, line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		key := source + "|" + line
		if seen[key] {
			return
		}
		seen[key] = true

		severity := Info
		desc := ""
		for _, p := range patterns {
			if p.re.MatchString(line) {
				severity = Critical
				desc = p.desc
				break
			}
		}
		detail := fmt.Sprintf("Cron entry — review: %s", line)
		if desc != "" {
			detail = fmt.Sprintf("%s: %s", desc, line)
		}
		*findings = append(*findings, Finding{
			Severity: severity,
			Check:    "Server Cron Audit",
			Detail:   detail,
			File:     source,
		})
	}

	readFile := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, l := range strings.Split(string(data), "\n") {
			addEntry(path, l)
		}
	}

	if os.Geteuid() == 0 {
		// Root can see every user's crontab — this is where a persistence
		// backdoor tied to a different system user (e.g. the PHP-FPM pool
		// user, not root) would actually live.
		readFile("/etc/crontab")
		for _, dir := range []string{"/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				readFile(filepath.Join(dir, e.Name()))
			}
		}
	} else {
		// Not root — can only see our own crontab. Say so explicitly
		// rather than silently reporting an incomplete picture.
		out, err := exec.Command("crontab", "-l").Output()
		if err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				addEntry("crontab -l (current user)", l)
			}
		}
		*findings = append(*findings, Finding{
			Severity: Info,
			Check:    "Server Cron Audit",
			Detail:   "Not running as root — only the current user's crontab was checked. Run with sudo to audit every system user's cron (this is where a PHP-FPM-user backdoor would hide).",
		})
	}
}

// ──────────────────────────────────────────────
// HELPER: Scan a file against compiled patterns
// ──────────────────────────────────────────────

type matchResult struct {
	line    int
	desc    string
	context string
	weight  int
}

func scanFileForPatterns(path string, patterns []*compiledPattern) []matchResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []matchResult
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, p := range patterns {
			if p.re.MatchString(line) {
				ctx := line
				if len(ctx) > 120 {
					ctx = ctx[:120] + "…"
				}
				results = append(results, matchResult{
					line:    lineNum,
					desc:    p.desc,
					context: ctx,
					weight:  p.weight,
				})
				break // one match per line is enough
			}
		}
	}
	return results
}
