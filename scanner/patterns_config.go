package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// customPatternEntry is the on-disk shape of one entry in the operator's
// cfg/custom_patterns.json. Weight is a string ("low"/"medium"/"high") so
// whoever is editing the file by hand doesn't need to remember the internal
// integer scale used in confidence.go.
type customPatternEntry struct {
	Check   string `json:"check"` // php | functions | js | db — defaults to php
	Pattern string `json:"pattern"`
	Desc    string `json:"desc"`
	Weight  string `json:"weight"` // low | medium | high — defaults to low
}

type customPatternsFile struct {
	Patterns []customPatternEntry `json:"patterns"`
}

// weightFromString maps the human-friendly config value to the internal
// weight scale. Unrecognized/empty values fall back to WeightLow rather
// than erroring, so a typo downgrades a signal instead of ever silently
// upgrading one to Critical.
func weightFromString(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return WeightHigh
	case "medium", "med":
		return WeightMedium
	default:
		return WeightLow
	}
}

// loadCustomPatterns reads path (cfg/custom_patterns.json by default) and
// merges every entry into the matching built-in pattern list, keyed by its
// "check" field. A missing file is not an error. Called once per Run(),
// before any site is scanned — every subsequent compilePatterns() call for
// the rest of the process picks up the merged list.
func loadCustomPatterns(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var f customPatternsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	for _, e := range f.Patterns {
		if strings.TrimSpace(e.Pattern) == "" {
			continue
		}

		desc := e.Desc
		if desc == "" {
			desc = "custom pattern: " + e.Pattern
		}

		def := PatternDef{Pattern: e.Pattern, Desc: desc, Weight: weightFromString(e.Weight)}

		switch strings.ToLower(strings.TrimSpace(e.Check)) {
		case "functions":
			FunctionsPHPPatterns = append(FunctionsPHPPatterns, def)
		case "js", "javascript":
			JSInjectionPatterns = append(JSInjectionPatterns, def)
		case "db", "database":
			DBMalwarePatterns = append(DBMalwarePatterns, def)
		default:
			PHPMalwarePatterns = append(PHPMalwarePatterns, def)
		}
	}

	return nil
}
