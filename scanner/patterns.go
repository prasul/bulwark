package scanner

// PHPMalwarePatterns are high-confidence PHP malware indicators.
// These are tuned to minimize false positives by requiring specific
// dangerous combinations rather than individual function names.
//
// Each pattern carries a Weight (see confidence.go):
//   WeightHigh   — the pattern alone is specific enough to act on (a named
//                  webshell string, a 3-layer decode chain, eval() fed
//                  directly by a superglobal). No corroboration needed.
//   WeightMedium — a dangerous combination that is *usually* bad but has
//                  known legitimate uses in some plugins/themes. Needs a
//                  second signal (another Medium, or a couple of Lows)
//                  before it's treated as Critical.
//   WeightLow    — a generic building block that shows up constantly in
//                  legitimate code (contact-form mail(), file uploads,
//                  short curl var names, custom-header checks). Noisy
//                  alone; only meaningful stacked with something else.
var PHPMalwarePatterns = []PatternDef{
	// === Obfuscated eval/execution (high confidence) ===
	{Pattern: `eval\s*\(\s*base64_decode`, Desc: "eval(base64_decode(…))", Weight: WeightHigh},
	{Pattern: `eval\s*\(\s*gzinflate`, Desc: "eval(gzinflate(…))", Weight: WeightHigh},
	{Pattern: `eval\s*\(\s*gzuncompress`, Desc: "eval(gzuncompress(…))", Weight: WeightHigh},
	{Pattern: `eval\s*\(\s*str_rot13`, Desc: "eval(str_rot13(…))", Weight: WeightHigh},
	{Pattern: `eval\s*\(\s*rawurldecode`, Desc: "eval(rawurldecode(…))", Weight: WeightHigh},
	{Pattern: `eval\s*\(\s*hex2bin`, Desc: "eval(hex2bin(…))", Weight: WeightHigh},
	{Pattern: `assert\s*\(\s*base64_decode`, Desc: "assert(base64_decode(…))", Weight: WeightHigh},
	{Pattern: `assert\s*\(\s*\$_`, Desc: "assert with superglobal input", Weight: WeightHigh},

	// === Dynamic function name construction (backdoor technique) ===
	// Medium: referencing these function names as strings is a classic
	// dynamic-dispatch backdoor trick, but also shows up in legitimate
	// is_callable()/reflection-based test and compatibility shims.
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']assert["']`, Desc: "variable holding 'assert' string", Weight: WeightMedium},
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']create_function["']`, Desc: "variable holding 'create_function'", Weight: WeightMedium},
	{Pattern: `\$[a-zA-Z_]\w*\s*=\s*["']str_rot13["']`, Desc: "variable holding 'str_rot13'", Weight: WeightMedium},

	// === Hex/char encoding tricks ===
	// Low: base64 blobs and chr()/hex chains are everywhere in legitimately
	// encoded assets (fonts, images, license keys, serialized data).
	{Pattern: `\\x63\\x72\\x65\\x61\\x74\\x65`, Desc: "hex-encoded 'create'", Weight: WeightLow},
	{Pattern: `chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)`, Desc: "chr() concatenation chain", Weight: WeightLow},
	{Pattern: `hex2bin\s*\(\s*["'][0-9a-fA-F]{20,}`, Desc: "hex2bin with long hex string", Weight: WeightLow},
	{Pattern: `[A-Za-z0-9+/=]{300,}`, Desc: "very long base64 blob (300+ chars)", Weight: WeightLow},

	// === Backdoor / webshell — command execution via user input ===
	// High: a raw HTTP superglobal driving a shell exec function has
	// essentially no legitimate use in WordPress PHP.
	{Pattern: `passthru\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "passthru() with user input", Weight: WeightHigh},
	{Pattern: `system\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "system() with user input", Weight: WeightHigh},
	{Pattern: `shell_exec\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "shell_exec() with user input", Weight: WeightHigh},
	{Pattern: `exec\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "exec() with user input", Weight: WeightHigh},
	{Pattern: `popen\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "popen() with user input", Weight: WeightHigh},
	{Pattern: `proc_open\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "proc_open() with user input", Weight: WeightHigh},
	// Low: matches on a broad key-name substring — $_POST['password'] on
	// any login/contact form trips this constantly.
	{Pattern: `\$_(GET|POST|REQUEST)\s*\[.{0,10}(cmd|pass|pw|shell|exec)`, Desc: "superglobal with suspicious key", Weight: WeightLow},
	{Pattern: `if\s*\(\s*md5\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "md5 password check on input", Weight: WeightMedium},

	// === Dynamic call with user input ===
	{Pattern: `\$[a-zA-Z_]\w*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "variable function call with user input", Weight: WeightHigh},
	// Medium: call_user_func with user data appears in some legitimate
	// dynamic-dispatch/router code, though it's still risky.
	{Pattern: `call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)`, Desc: "call_user_func with user input", Weight: WeightMedium},
	{Pattern: `preg_replace\s*\(.*/e[^a-z]`, Desc: "preg_replace with /e modifier (code exec)", Weight: WeightMedium},
	{Pattern: `create_function\s*\(`, Desc: "create_function() (deprecated, used in exploits)", Weight: WeightMedium},
	// Low: Reflection is ubiquitous in modern PHP frameworks/DI containers.
	{Pattern: `ReflectionFunction\s*\(`, Desc: "ReflectionFunction (dynamic code exec)", Weight: WeightLow},

	// === Remote code/file fetching with user input ===
	{Pattern: `file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, Desc: "file_get_contents with user input", Weight: WeightMedium},
	{Pattern: `curl_setopt.*CURLOPT_URL.*\$_(GET|POST|REQUEST)`, Desc: "curl with user-supplied URL", Weight: WeightMedium},
	{Pattern: `gzinflate\s*\(\s*base64_decode`, Desc: "gzinflate(base64_decode(…))", Weight: WeightHigh},
	{Pattern: `gzuncompress\s*\(\s*base64_decode`, Desc: "gzuncompress(base64_decode(…))", Weight: WeightHigh},
	{Pattern: `str_rot13\s*\(\s*base64_decode`, Desc: "str_rot13(base64_decode(…))", Weight: WeightHigh},

	// === Known webshell signatures (named strings — definitive alone) ===
	{Pattern: `(?i)anonymousfox`, Desc: "AnonymousFox webshell", Weight: WeightHigh},
	{Pattern: `(?i)r57shell`, Desc: "r57shell webshell", Weight: WeightHigh},
	{Pattern: `(?i)c99shell`, Desc: "c99shell webshell", Weight: WeightHigh},
	{Pattern: `(?i)FilesMan`, Desc: "FilesMan webshell", Weight: WeightHigh},
	{Pattern: `(?i)b374k`, Desc: "b374k webshell", Weight: WeightHigh},
	{Pattern: `(?i)IndoXploit`, Desc: "IndoXploit webshell", Weight: WeightHigh},
	{Pattern: `(?i)ALFA_DATA`, Desc: "ALFA shell", Weight: WeightHigh},
	{Pattern: `(?i)alfa-shell`, Desc: "alfa-shell webshell", Weight: WeightHigh},
	{Pattern: `WSO\s*[0-9]`, Desc: "WSO webshell", Weight: WeightHigh},
	{Pattern: `(?i)Upl0ader`, Desc: "Upl0ader webshell", Weight: WeightHigh},

	// === Deep obfuscation indicators ===
	// Low: variable variables ($$var) are used by some legitimate
	// metaprogramming code too.
	{Pattern: `\$\{\$[a-zA-Z_]`, Desc: "variable variable ($$var)", Weight: WeightLow},
	{Pattern: `O0O0OO0O0O0`, Desc: "common obfuscation variable pattern", Weight: WeightHigh},

	// === WordPress-specific injection ===
	{Pattern: `add_(action|filter)\s*\(.*eval\s*\(`, Desc: "WP hook with eval()", Weight: WeightHigh},
	{Pattern: `wp_remote_(get|post)\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "wp_remote with user input", Weight: WeightMedium},
	// Low: wp-login.php itself and many plugins legitimately do
	// wp_redirect($_GET['redirect_to']) style flows.
	{Pattern: `wp_redirect\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "wp_redirect with user input", Weight: WeightLow},

	// === SQL injection via $wpdb with unsanitized input ===
	{Pattern: `\$wpdb->query\s*\(\s*["']\s*SELECT.*\$_(GET|POST|REQUEST)`, Desc: "$wpdb->query with user input", Weight: WeightMedium},
	{Pattern: `\$wpdb->get_results\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "$wpdb->get_results with user input", Weight: WeightMedium},

	// === Spam/mailer indicators ===
	// Low: virtually every contact-form plugin (CF7, WPForms, Gravity
	// Forms) legitimately calls mail()/wp_mail() with $_POST fields.
	{Pattern: `mail\s*\(.*\$_(GET|POST|REQUEST)`, Desc: "mail() with user input", Weight: WeightLow},
	{Pattern: `@sendmail`, Desc: "@sendmail directive", Weight: WeightMedium},

	// === Ported from hackchk.sh backdoor scan (2025-2026 campaigns) ===
	{Pattern: `eval\s*\(\s*\$_REQUEST`, Desc: "eval($_REQUEST)", Weight: WeightHigh},
	{Pattern: `(?i)AnonymoX9jaTeam`, Desc: "AnonymoX9jaTeam signature", Weight: WeightHigh},
	{Pattern: `(?i)blackpanther1337`, Desc: "blackpanther1337 signature", Weight: WeightHigh},
	{Pattern: `(?i)shellx\.org`, Desc: "shellx.org callback reference", Weight: WeightHigh},
	{Pattern: `(?i)womndo\.com`, Desc: "womndo.com callback reference", Weight: WeightHigh},
	{Pattern: `(?i)xXsUIssAZ|ALgR_Dz|An0n_3xPloiTeR`, Desc: "known defacement signature", Weight: WeightHigh},
	{Pattern: `str_split\s*\(\s*rawurldecode\s*\(\s*str_rot13`, Desc: "str_split(rawurldecode(str_rot13(…)))", Weight: WeightHigh},
	{Pattern: `base64_decode\s*\(\s*rawurldecode\s*\(\s*\(?urlencode\s*\(\s*urldecode\s*\(\s*\$_REQUEST`, Desc: "layered decode of $_REQUEST", Weight: WeightHigh},
	// Low: matches ANY 5-character variable name assigned from curl_init()
	// — e.g. `$curl1 = curl_init();` is completely ordinary PHP.
	{Pattern: `\$[a-zA-Z0-9]{5}\s*=\s*curl_init`, Desc: "randomized-var curl_init (dropper pattern)", Weight: WeightLow},
	{Pattern: `create_function\s*\(\s*["']["']\s*,\s*rawurldecode`, Desc: "create_function with rawurldecode payload", Weight: WeightHigh},
	// Low: this is the textbook-correct way to handle PHP file uploads
	// ($_FILES['x']['tmp_name']) — every upload feature in WP does this.
	{Pattern: `move_uploaded_file\s*\(\s*\$_`, Desc: "move_uploaded_file() with superglobal input", Weight: WeightLow},
	// Low: reading a custom HTTP header is extremely common (CDN/proxy
	// headers like HTTP_CF_CONNECTING_IP, HTTP_X_FORWARDED_FOR, API keys).
	{Pattern: `if\s*\(\s*isset\s*\(\s*\$_SERVER\[.HTTP_`, Desc: "conditional gate on custom HTTP header", Weight: WeightLow},
	{Pattern: `\\x63\\x72\\x65\\x61\\x74\\x65\\x5f\\x75\\x6e\\x63\\x74\\x69\\x6f\\x6e`, Desc: "hex-encoded 'create_function'", Weight: WeightHigh},
	{Pattern: `if\s*\(\s*\$_GET\[.pw.\]\s*==\s*\$password\s*\)`, Desc: "hardcoded password gate on $_GET['pw']", Weight: WeightMedium},
	// Medium: the sequence is specific, but error-suppression before an
	// ABSPATH header guard is also common defensive boilerplate.
	{Pattern: `error_reporting\s*\(\s*0\s*\)\s*;\s*ini_set\s*\(\s*["']display_errors["']\s*,\s*0\s*\)\s*;\s*if\s*\(\s*!\s*defined`, Desc: "error-suppression preamble (webshell boilerplate)", Weight: WeightMedium},
	{Pattern: `get_magic_quotes_gpc\s*\(\s*\)\s*\)\s*\{\s*foreach\s*\(\s*\$_POST`, Desc: "legacy magic_quotes stripslashes wrapper (webshell boilerplate)", Weight: WeightMedium},
}

// PHPCommentBackdoorPatterns match payloads hidden in PHP comment openers —
// grep -F "<?php /*-" in the original bash scanner. Kept separate since
// it's a literal substring match, not a regex pattern. Specific enough to
// act on alone.
var PHPCommentBackdoorPatterns = []PatternDef{
	{Pattern: `<\?php\s*/\*-`, Desc: "payload hidden after fake comment opener <?php /*-", Weight: WeightHigh},
}

// FunctionsPHPPatterns are specifically for detecting injections in
// functions.php and theme files — wp_head hook abuse, C2 callbacks, etc.
var FunctionsPHPPatterns = []PatternDef{
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*wp_remote_(post|get)`, Desc: "wp_head hook with remote request (C2 callback)", Weight: WeightHigh},
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*file_get_contents`, Desc: "wp_head hook fetching remote content", Weight: WeightHigh},
	{Pattern: `add_action\s*\(\s*['"]wp_head['"].*curl_exec`, Desc: "wp_head hook with curl (C2 callback)", Weight: WeightHigh},
	{Pattern: `add_action\s*\(\s*['"]wp_footer['"].*wp_remote_(post|get)`, Desc: "wp_footer hook with remote request", Weight: WeightHigh},
	// Medium: legitimate license-check/update-check plugins commonly ping
	// their server on the init hook.
	{Pattern: `add_action\s*\(\s*['"]init['"].*wp_remote_(post|get)`, Desc: "init hook with remote request", Weight: WeightMedium},
	{Pattern: `wp_remote_post\s*\(.*echo\s+wp_remote_retrieve_body`, Desc: "fetch-and-echo pattern (classic injection)", Weight: WeightHigh},
	{Pattern: `get_option\s*\(.*unserialize.*create_function`, Desc: "DB-stored serialized code execution", Weight: WeightHigh},
	{Pattern: `add_action\s*\(.*get_option.*eval`, Desc: "hook loading eval from DB option", Weight: WeightHigh},
	// Persistent admin creator backdoor (2025 pattern)
	{Pattern: `username_exists\s*\(.*wp_create_user`, Desc: "persistent admin creator backdoor", Weight: WeightHigh},
	// Medium: legitimate provisioning/staging/migration scripts also
	// create admin users programmatically.
	{Pattern: `wp_insert_user.*administrator`, Desc: "programmatic admin user creation", Weight: WeightMedium},
}

// JSInjectionPatterns detect malicious JavaScript injected into
// theme header.php, footer.php, and .js files.
var JSInjectionPatterns = []PatternDef{
	{Pattern: `<script[^>]*src\s*=\s*["']https?://[^"']*\.(ru|cn|tk|ml|ga|cf|top|xyz|pw|buzz)/`, Desc: "script loading from suspicious TLD", Weight: WeightMedium},
	// Low: this is a bare allowlist-miss — Stripe, PayPal, Intercom,
	// Hotjar, Mailchimp, Typekit, Segment, YouTube etc. all trip it.
	{Pattern: `<script[^>]*src\s*=\s*["']https?://(?!.*(?:googleapis|gstatic|cloudflare|jquery|wordpress|wp\.com|gravatar|google|facebook|twitter|cdnjs|unpkg|jsdelivr))`, Desc: "script loading from unknown external domain", Weight: WeightLow},
	// Low: minifiers/obfuscator plugins (webpack, terser) produce _0x-style
	// var names in a lot of legitimate vendor bundles.
	{Pattern: `var\s+_0x[a-f0-9]{4}\s*=`, Desc: "obfuscated JS variable (_0x pattern)", Weight: WeightLow},
	{Pattern: `document\.write\s*\(\s*unescape`, Desc: "document.write(unescape(…))", Weight: WeightMedium},
	{Pattern: `String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+`, Desc: "String.fromCharCode chain", Weight: WeightLow},
	{Pattern: `atob\s*\(\s*["'][A-Za-z0-9+/=]{40,}`, Desc: "atob() with long base64 payload", Weight: WeightLow},
	{Pattern: `eval\s*\(\s*atob`, Desc: "eval(atob(…))", Weight: WeightHigh},
	// Low: this is the signature of the Dean Edwards Packer, a genuinely
	// popular *legitimate* minifier used by countless themes/plugins.
	{Pattern: `eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k`, Desc: "eval(p,a,c,k) packer", Weight: WeightLow},
	{Pattern: `window\[["']location["']\]\s*=`, Desc: "window['location'] redirect", Weight: WeightLow},
	{Pattern: `document\.createElement\s*\(\s*["']iframe["'\s]*\).*display\s*:\s*none`, Desc: "hidden iframe creation", Weight: WeightMedium},
	{Pattern: `data-cfasync\s*=\s*["']false["'].*src\s*=\s*["']https?://(?!.*cloudflare)`, Desc: "cfasync bypass with non-Cloudflare script", Weight: WeightMedium},
	// Crypto miner patterns
	{Pattern: `(?i)coinhive\.min\.js`, Desc: "CoinHive crypto miner", Weight: WeightHigh},
	{Pattern: `(?i)cryptonight`, Desc: "CryptoNight miner reference", Weight: WeightHigh},
	{Pattern: `(?i)miner\.start\s*\(`, Desc: "miner.start() call", Weight: WeightMedium},
}

// DBMalwarePatterns detect malicious content stored in the WordPress database
var DBMalwarePatterns = []PatternDef{
	{Pattern: `<script[^>]*src=["']https?://`, Desc: "external script tag in DB content", Weight: WeightMedium},
	// Low: eval()/base64_decode()/atob()/fromCharCode() alone show up
	// constantly in legitimately serialized page-builder/widget content.
	{Pattern: `eval\s*\(`, Desc: "eval() in DB content", Weight: WeightLow},
	{Pattern: `base64_decode\s*\(`, Desc: "base64_decode in DB content", Weight: WeightLow},
	{Pattern: `atob\s*\(`, Desc: "atob() in DB content", Weight: WeightLow},
	{Pattern: `String\.fromCharCode\s*\(`, Desc: "String.fromCharCode in DB", Weight: WeightLow},
	{Pattern: `document\.write\s*\(\s*unescape`, Desc: "document.write(unescape()) in DB", Weight: WeightMedium},
	{Pattern: `<iframe[^>]*style=["'][^"]*display\s*:\s*none`, Desc: "hidden iframe in DB content", Weight: WeightMedium},
	// High: DB fields should never contain a raw PHP open tag.
	{Pattern: `<\?php`, Desc: "PHP code injected into DB content", Weight: WeightHigh},
	{Pattern: `(?i)casino|viagra|cialis|pharma|porn|xxx|adult|dating`, Desc: "SEO spam keywords in DB", Weight: WeightMedium},
	{Pattern: `gzinflate\s*\(\s*base64_decode`, Desc: "gzinflate(base64_decode()) in DB", Weight: WeightHigh},
	{Pattern: `wp_check_hash`, Desc: "wp_check_hash (known malware key)", Weight: WeightHigh},
	{Pattern: `auto_update_setting`, Desc: "fake auto_update_setting", Weight: WeightHigh},
	{Pattern: `(?i)coinhive`, Desc: "crypto miner reference in DB", Weight: WeightHigh},
}

// SuspiciousWPOptionKeys are wp_options keys that should never exist
var SuspiciousWPOptionKeys = []string{
	"auto_prepend",
	"wp_check_hash",
	"page_option",              // used by serialized code exec malware
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

// HighRiskSnippetPlugins are plugins that let an attacker (or a compromised
// admin account) execute arbitrary PHP directly from the DB or wp-admin —
// no file-write access needed. Legitimate uses exist, so these are flagged
// for review, not treated as malware on their own.
var HighRiskSnippetPlugins = []string{
	"wpcode",
	"insert-headers-and-footers",
	"wp-file-manager",
	"code-snippets",
	"header-footer",
}

// SnippetOptionKeys are wp_options rows where the above plugins persist
// raw PHP/HTML payloads. A hit here means there's injectable code sitting
// in the DB even if no plugin file on disk looks wrong.
var SnippetOptionKeys = []string{
	"wpcode_snippets",
	"ihaf_settings",
	"code_snippets_db",
}

// PatternDef is a regex pattern with a human-readable description and a
// confidence Weight (see confidence.go for how Weight becomes Severity).
type PatternDef struct {
	Pattern string
	Desc    string
	Weight  int
}
