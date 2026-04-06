package scanner

import (
	"bufio"
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
		out = append(out, &compiledPattern{re: re, desc: d.Desc})
	}
	return out
}

type compiledPattern struct {
	re   *regexp.Regexp
	desc string
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

	// Also check core files (wp-*.php in root)
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
			*findings = append(*findings, Finding{
				Severity: Warning,
				Check:    "Recently Modified",
				Detail:   fmt.Sprintf("Core file modified within %d days (mtime: %s)", recentDays, info.ModTime().Format("2006-01-02 15:04")),
				File:     name,
			})
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
				*findings = append(*findings, Finding{
					Severity: severity,
					Check:    "Recently Modified",
					Detail:   fmt.Sprintf("File modified within %d days (mtime: %s)", recentDays, info.ModTime().Format("2006-01-02 15:04")),
					File:     rel,
				})
			}
			return nil
		})
	}
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
			ctx := make([]string, 0, 3)
			for i, m := range matches {
				if i >= 3 {
					break
				}
				ctx = append(ctx, fmt.Sprintf("L%d: %s", m.line, m.desc))
			}
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "PHP Malware Scan",
				Detail:   strings.Join(ctx, " | "),
				File:     rel,
				Line:     matches[0].line,
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
		for _, m := range matches {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Theme Hook Injection",
				Detail:   fmt.Sprintf("%s — %s", m.desc, m.context),
				File:     rel,
				Line:     m.line,
			})
		}
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
		for _, m := range matches {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "JS Injection",
				Detail:   fmt.Sprintf("%s — %s", m.desc, m.context),
				File:     rel,
				Line:     m.line,
			})
		}
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
		for _, m := range matches {
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "JS Injection",
				Detail:   fmt.Sprintf("%s — %s", m.desc, m.context),
				File:     e.Name(),
				Line:     m.line,
			})
		}
	}
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
			for _, m := range matches {
				*findings = append(*findings, Finding{
					Severity: Critical,
					Check:    "mu-plugins Malware",
					Detail:   fmt.Sprintf("%s — %s", m.desc, m.context),
					File:     rel,
					Line:     m.line,
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
				Severity: Critical,
				Check:    "Database Scan",
				Detail:   fmt.Sprintf("Suspicious DB content: %s", pd.Desc),
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
			ctx := make([]string, 0, 3)
			for i, m := range matches {
				if i >= 3 {
					break
				}
				ctx = append(ctx, fmt.Sprintf("L%d: %s", m.line, m.desc))
			}
			*findings = append(*findings, Finding{
				Severity: Critical,
				Check:    "Plugin Malware",
				Detail:   strings.Join(ctx, " | "),
				File:     rel,
			})
		}
		return nil
	})
}

// ──────────────────────────────────────────────
// HELPER: Scan a file against compiled patterns
// ──────────────────────────────────────────────

type matchResult struct {
	line    int
	desc    string
	context string
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
				})
				break // one match per line is enough
			}
		}
	}
	return results
}
