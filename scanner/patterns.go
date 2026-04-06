package scanner

// PHPMalwarePatterns are high-confidence PHP malware indicators.
// These are tuned to minimize false positives by requiring specific
// dangerous combinations rather than individual function names.
var PHPMalwarePatterns = []PatternDef{
	// === Obfuscated eval/execution (high confidence) ===
	{Pattern: `eval\s*\(\s*base64_decode`, Desc: "eval(base64_decode(…))"},
	{Pattern: `eval\s*\(\s*gzinflate`, Desc: "eval(gzinflate(…))"},
	{Pattern: `eval\s*\(\s*gzuncompress`, Desc: "eval(gzuncompress(…))"},
	{Pattern: `eval\s*\(\s*str_rot13`, Desc: "eval(str_rot13(…))"},
	{Pattern: `eval\s*\(\s*rawurldecode`, Desc: "eval(rawurldecode(…))"},
	{Pattern: `eval\s*\(\s*hex2bin`, Desc: "eval(hex2bin(…))"},
	{Pattern: `assert\s*\(\s*base64_decode`, Desc: "assert(base64_decode(…))"},
	{Pattern: `assert\s*\(\s*\$_`, Desc: "assert with superglobal input"},

	// === Dynamic function name construction (backdoor technique) ===
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']assert["']`, Desc: "variable holding 'assert' string"},
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']create_function["']`, Desc: "variable holding 'create_function'"},
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']str_rot13["']`, Desc: "variable holding 'str_rot13'"},

	// === Hex/char encoding tricks ===
	{Pattern: `\\x63\\x72\\x65\\x61\\x74\\x65`, Desc: "hex-encoded 'create'"},
	{Pattern: `chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)`, Desc: "chr() concatenation chain"},
	{Pattern: `hex2bin\s*\(\s*["'][0-9a-fA-F]{20,}`, Desc: "hex2bin with long hex string"},
	{Pattern: `[A-Za-z0-9+/=]{300,}`, Desc: "very long base64 blob (300+ chars)"},

	// === Backdoor / webshell — command execution via user input ===
	{Pattern: `passthru\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "passthru() with user input"},
	{Pattern: `system\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "system() with user input"},
	{Pattern: `shell_exec\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "shell_exec() with user input"},
	{Pattern: `exec\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "exec() with user input"},
	{Pattern: `popen\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "popen() with user input"},
	{Pattern: `proc_open\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "proc_open() with user input"},
	{Pattern: `\$_(GET|POST|REQUEST)\s*\[.{0,10}(cmd|pass|pw|shell|exec)`, Desc: "superglobal with suspicious key"},
	{Pattern: `if\s*\(\s*md5\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "md5 password check on input"},

	// === Dynamic call with user input ===
	{Pattern: `\$[a-zA-Z_]\w*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "variable function call with user input"},
	{Pattern: `call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "call_user_func with user input"},
	{Pattern: `preg_replace\s*\(.*/e[^a-z]`, Desc: "preg_replace with /e modifier (code exec)"},
	{Pattern: `create_function\s*\(`, Desc: "create_function() (deprecated, used in exploits)"},
	{Pattern: `ReflectionFunction\s*\(`, Desc: "ReflectionFunction (dynamic code exec)"},

	// === Remote code/file fetching with user input ===
	{Pattern: `file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "file_get_contents with user input"},
	{Pattern: `curl_setopt.*CURLOPT_URL.*\$_(GET|POST|REQUEST)`, Desc: "curl with user-supplied URL"},
	{Pattern: `gzinflate\s*\(\s*base64_decode`, Desc: "gzinflate(base64_decode(…))"},
	{Pattern: `gzuncompress\s*\(\s*base64_decode`, Desc: "gzuncompress(base64_decode(…))"},
	{Pattern: `str_rot13\s*\(\s*base64_decode`, Desc: "str_rot13(base64_decode(…))"},

	// === Known webshell signatures ===
	{Pattern: `(?i)anonymousfox`, Desc: "AnonymousFox webshell"},
	{Pattern: `(?i)r57shell`, Desc: "r57shell webshell"},
	{Pattern: `(?i)c99shell`, Desc: "c99shell webshell"},
	{Pattern: `(?i)FilesMan`, Desc: "FilesMan webshell"},
	{Pattern: `(?i)b374k`, Desc: "b374k webshell"},
	{Pattern: `(?i)IndoXploit`, Desc: "IndoXploit webshell"},
	{Pattern: `(?i)ALFA_DATA`, Desc: "ALFA shell"},
	{Pattern: `(?i)alfa-shell`, Desc: "alfa-shell webshell"},
	{Pattern: `WSO\s*[0-9]`, Desc: "WSO webshell"},
	{Pattern: `(?i)Upl0ader`, Desc: "Upl0ader webshell"},

	// === Deep obfuscation indicators ===
	{Pattern: `\$\{\$[a-zA-Z_]`, Desc: "variable variable ($$var)"},
	{Pattern: `O0O0OO0O0O0`, Desc: "common obfuscation variable pattern"},

	// === WordPress-specific injection ===
	{Pattern: `add_(action|filter)\s*\(.*eval\s*\(`, Desc: "WP hook with eval()"},
	{Pattern: `wp_remote_(get|post)\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "wp_remote with user input"},
	{Pattern: `wp_redirect\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "wp_redirect with user input"},

	// === SQL injection via $wpdb with unsanitized input ===
	{Pattern: `\$wpdb->query\s*\(\s*["']\s*SELECT.*\$_(GET|POST|REQUEST)`, Desc: "$wpdb->query with user input"},
	{Pattern: `\$wpdb->get_results\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "$wpdb->get_results with user input"},

	// === Spam/mailer indicators ===
	{Pattern: `mail\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "mail() with user input"},
	{Pattern: `@sendmail`, Desc: "@sendmail directive"},
}

// FunctionsPHPPatterns are specifically for detecting injections in
// functions.php and theme files — wp_head hook abuse, C2 callbacks, etc.
var FunctionsPHPPatterns = []PatternDef{
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*wp_remote_(post|get)`, Desc: "wp_head hook with remote request (C2 callback)"},
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*file_get_contents`, Desc: "wp_head hook fetching remote content"},
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*curl_exec`, Desc: "wp_head hook with curl (C2 callback)"},
	{Pattern: `add_action\s*\(\s*['"]wp_footer['"].*wp_remote_(post|get)`, Desc: "wp_footer hook with remote request"},
	{Pattern: `add_action\s*\(\s*['"]init['"].*wp_remote_(post|get)`, Desc: "init hook with remote request"},
	{Pattern: `wp_remote_post\s*\(.*echo\s+wp_remote_retrieve_body`, Desc: "fetch-and-echo pattern (classic injection)"},
	{Pattern: `get_option\s*\(.*unserialize.*create_function`, Desc: "DB-stored serialized code execution"},
	{Pattern: `add_action\s*\(.*get_option.*eval`, Desc: "hook loading eval from DB option"},
	// Persistent admin creator backdoor (2025 pattern)
	{Pattern: `username_exists\s*\(.*wp_create_user`, Desc: "persistent admin creator backdoor"},
	{Pattern: `wp_insert_user.*administrator`, Desc: "programmatic admin user creation"},
}

// JSInjectionPatterns detect malicious JavaScript injected into
// theme header.php, footer.php, and .js files.
var JSInjectionPatterns = []PatternDef{
	{Pattern: `<script[^>]*src\s*=\s*["']https?://[^"']*\.(ru|cn|tk|ml|ga|cf|top|xyz|pw|buzz)/`, Desc: "script loading from suspicious TLD"},
	{Pattern: `<script[^>]*src\s*=\s*["']https?://(?!.*(?:googleapis|gstatic|cloudflare|jquery|wordpress|wp\.com|gravatar|google|facebook|twitter|cdnjs|unpkg|jsdelivr))`, Desc: "script loading from unknown external domain"},
	{Pattern: `var\s+_0x[a-f0-9]{4}\s*=`, Desc: "obfuscated JS variable (_0x pattern)"},
	{Pattern: `document\.write\s*\(\s*unescape`, Desc: "document.write(unescape(…))"},
	{Pattern: `String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+`, Desc: "String.fromCharCode chain"},
	{Pattern: `atob\s*\(\s*["'][A-Za-z0-9+/=]{40,}`, Desc: "atob() with long base64 payload"},
	{Pattern: `eval\s*\(\s*atob`, Desc: "eval(atob(…))"},
	{Pattern: `eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k`, Desc: "eval(p,a,c,k) packer"},
	{Pattern: `window\[["']location["']\]\s*=`, Desc: "window['location'] redirect"},
	{Pattern: `document\.createElement\s*\(\s*["']iframe["'\s]*\).*display\s*:\s*none`, Desc: "hidden iframe creation"},
	{Pattern: `data-cfasync\s*=\s*["']false["'].*src\s*=\s*["']https?://(?!.*cloudflare)`, Desc: "cfasync bypass with non-Cloudflare script"},
	// Crypto miner patterns
	{Pattern: `(?i)coinhive\.min\.js`, Desc: "CoinHive crypto miner"},
	{Pattern: `(?i)cryptonight`, Desc: "CryptoNight miner reference"},
	{Pattern: `(?i)miner\.start\s*\(`, Desc: "miner.start() call"},
}

// DBMalwarePatterns detect malicious content stored in the WordPress database
var DBMalwarePatterns = []PatternDef{
	{Pattern: `<script[^>]*src=["']https?://`, Desc: "external script tag in DB content"},
	{Pattern: `eval\s*\(`, Desc: "eval() in DB content"},
	{Pattern: `base64_decode\s*\(`, Desc: "base64_decode in DB content"},
	{Pattern: `atob\s*\(`, Desc: "atob() in DB content"},
	{Pattern: `String\.fromCharCode\s*\(`, Desc: "String.fromCharCode in DB"},
	{Pattern: `document\.write\s*\(\s*unescape`, Desc: "document.write(unescape()) in DB"},
	{Pattern: `<iframe[^>]*style=["'][^"]*display\s*:\s*none`, Desc: "hidden iframe in DB content"},
	{Pattern: `<\?php`, Desc: "PHP code injected into DB content"},
	{Pattern: `(?i)casino|viagra|cialis|pharma|porn|xxx|adult|dating`, Desc: "SEO spam keywords in DB"},
	{Pattern: `gzinflate\s*\(\s*base64_decode`, Desc: "gzinflate(base64_decode()) in DB"},
	{Pattern: `wp_check_hash`, Desc: "wp_check_hash (known malware key)"},
	{Pattern: `auto_update_setting`, Desc: "fake auto_update_setting"},
	{Pattern: `(?i)coinhive`, Desc: "crypto miner reference in DB"},
}

// SuspiciousWPOptionKeys are wp_options keys that should never exist
var SuspiciousWPOptionKeys = []string{
	"auto_prepend",
	"wp_check_hash",
	"page_option",    // used by serialized code exec malware
	"_site_transient_browser_", // sometimes abused
}

// KnownCleanPHPPaths are paths where PHP patterns commonly appear
// legitimately. Files matching these won't be flagged for general
// PHP pattern scanning (they still get functions.php-specific checks).
var KnownCleanPHPPaths = []string{
	"wp-admin/",
	"wp-includes/",
	// Well-known security plugins that contain detection signatures
	"wordfence",
	"sucuri",
	"ithemes-security",
	"all-in-one-wp-security",
	"anti-malware",
	"gotmls",
}

// PatternDef is a regex pattern with a human-readable description
type PatternDef struct {
	Pattern string
	Desc    string
}
