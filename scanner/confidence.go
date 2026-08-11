package scanner

// Confidence scoring turns a pile of independent pattern matches into one
// severity per file/finding, instead of treating every single regex hit as
// Critical. The idea: weak, generic signals (a long base64 blob, a custom
// HTTP header check, a short curl variable name) are individually common in
// legitimate code and shouldn't alone trigger a Critical alert. But several
// of them landing in the same file — or one genuinely specific signature —
// is a much stronger indicator. This mirrors how multi-signal malware
// scanners avoid flagging on a single weak match: corroboration lowers the
// false-positive rate without hiding anything from the reviewer.
//
// This is an independent design for wpscan and does not use or embed any
// third-party scanning engine or signature set.

// Weight tiers for PatternDef.Weight.
const (
	WeightLow    = 1 // generic building block, noisy alone (e.g. long base64 blob)
	WeightMedium = 2 // dangerous combination with some known legitimate uses
	WeightHigh   = 4 // specific enough to act on by itself (named signature, superglobal->eval)
)

// Score thresholds for turning an aggregated confidence score into Severity.
const (
	thresholdCritical = 4 // one High signal alone, or 2+ Medium/Low signals corroborating each other
	thresholdWarning  = 2 // a single Medium signal, or 2+ Low signals — worth a human look
)

// scoreMatches aggregates distinct pattern signals found in one file into a
// single confidence score and severity. The same pattern matching on
// multiple lines only counts once: what matters is how many *independent*
// signals fired, not how many lines happened to match.
func scoreMatches(matches []matchResult) (score int, severity Severity) {
	seen := make(map[string]bool, len(matches))

	for _, m := range matches {
		if seen[m.desc] {
			continue
		}
		seen[m.desc] = true
		score += m.weight
	}

	return score, severityForScore(score)
}

// severityForScore maps an aggregated confidence score to a Severity.
func severityForScore(score int) Severity {
	switch {
	case score >= thresholdCritical:
		return Critical
	case score >= thresholdWarning:
		return Warning
	default:
		return Info
	}
}

// severityForWeight maps a single pattern's own weight to a Severity, for
// checks that can't aggregate multiple signals together (e.g. one wp-cli
// query per pattern against the database, with no way to combine hits from
// the same row into one score).
func severityForWeight(weight int) Severity {
	switch {
	case weight >= WeightHigh:
		return Critical
	case weight >= WeightMedium:
		return Warning
	default:
		return Info
	}
}

// signalCount returns how many distinct patterns matched, for reporting
// alongside the score (e.g. "confidence 4, 2 signals").
func signalCount(matches []matchResult) int {
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		seen[m.desc] = true
	}
	return len(seen)
}
