package reports

import (
	"encoding/json"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func securityScore(rule sarifRule) (float64, bool) {
	raw := rule.Properties["security-severity"]
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var n float64
	if json.Unmarshal(raw, &n) != nil {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return 0, false
		}
		var err error
		n, err = strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
	}
	if n >= 0 && n <= 10 {
		return n, true
	}
	return 0, false
}
func findingSeverity(level string, score float64, known bool) string {
	if known {
		switch {
		case score >= 9:
			return "critical"
		case score >= 7:
			return "high"
		case score >= 4:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "informational"
		}
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "informational"
	}
}
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational":
		return 1
	}
	return 0
}
func sourceLanguage(declared, uri string) string {
	declared = strings.TrimSpace(declared)
	if declared != "" {
		base := strings.ToLower(strings.SplitN(declared, "/", 2)[0])
		aliases := languageAliases

		if value, ok := aliases[base]; ok {
			return value
		}
		return base
	}
	file := strings.ReplaceAll(uri, `\`, "/")
	if parsed, err := url.Parse(file); err == nil {
		file = parsed.Path
	}
	if decoded, err := url.PathUnescape(file); err == nil {
		file = decoded
	}
	extensions := languageExtensions
	if language, ok := extensions[strings.ToLower(path.Ext(file))]; ok {
		return language
	}
	return "Unknown"
}

var languageAliases = map[string]string{
	"go":         "Go",
	"golang":     "Go",
	"python":     "Python",
	"py":         "Python",
	"javascript": "JavaScript",
	"js":         "JavaScript",
	"typescript": "TypeScript",
	"ts":         "TypeScript",
	"csharp":     "C#",
	"c#":         "C#",
	"cpp":        "C++",
	"c++":        "C++",
	"c":          "C",
	"java":       "Java",
	"kotlin":     "Kotlin",
	"ruby":       "Ruby",
	"rust":       "Rust",
	"php":        "PHP",
	"swift":      "Swift",
	"shell":      "Shell",
	"bash":       "Shell",
	"sh":         "Shell",
	"scala":      "Scala",
	"html":       "HTML",
	"css":        "CSS",
	"sql":        "SQL",
	"yaml":       "YAML",
	"json":       "JSON",
	"terraform":  "Terraform",
	"hcl":        "Terraform",
}

var languageExtensions = map[string]string{
	".go":    "Go",
	".py":    "Python",
	".pyw":   "Python",
	".js":    "JavaScript",
	".jsx":   "JavaScript",
	".mjs":   "JavaScript",
	".cjs":   "JavaScript",
	".ts":    "TypeScript",
	".tsx":   "TypeScript",
	".mts":   "TypeScript",
	".cts":   "TypeScript",
	".cs":    "C#",
	".c":     "C",
	".h":     "C",
	".cc":    "C++",
	".cpp":   "C++",
	".cxx":   "C++",
	".hpp":   "C++",
	".java":  "Java",
	".kt":    "Kotlin",
	".kts":   "Kotlin",
	".rb":    "Ruby",
	".rs":    "Rust",
	".php":   "PHP",
	".swift": "Swift",
	".sh":    "Shell",
	".bash":  "Shell",
	".scala": "Scala",
	".html":  "HTML",
	".htm":   "HTML",
	".css":   "CSS",
	".scss":  "CSS",
	".sql":   "SQL",
	".yaml":  "YAML",
	".yml":   "YAML",
	".json":  "JSON",
	".tf":    "Terraform",
}
