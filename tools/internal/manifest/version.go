package manifest

import (
	"strings"
)

// CompareVersions does the numeric-dotted compare from api.md: 1.10.2 > 1.9.
// Returns -1, 0 or 1. A leading "v" is ignored, missing parts count as 0,
// and within a part the number is compared first, then any suffix
// (a bare number beats a suffixed one, so 1.0 > 1.0rc1).
func CompareVersions(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	n := max(len(pa), len(pb))
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := comparePart(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func splitVersion(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
}

func comparePart(x, y string) int {
	nx, sx := leadingNum(x)
	ny, sy := leadingNum(y)
	// compare digit strings by length then lexically, so huge numbers don't overflow
	if c := compareDigits(nx, ny); c != 0 {
		return c
	}
	switch {
	case sx == sy:
		return 0
	case sx == "":
		return 1
	case sy == "":
		return -1
	case sx < sy:
		return -1
	default:
		return 1
	}
}

func leadingNum(s string) (digits, rest string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return strings.TrimLeft(s[:i], "0"), strings.ToLower(s[i:])
}

func compareDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
