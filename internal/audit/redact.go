package audit

import (
	"strings"
)

// Redacted replaces the value of a sensitive key.
const Redacted = "[REDACTED]"

// sensitiveFragments are matched case-insensitively against key names after
// removing '-', '_' and '.'.
var sensitiveFragments = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey",
	"authorization", "privatekey", "credential", "cookie", "sessionid",
}

// IsSensitiveKey reports whether a field name looks like it holds a secret
// (password, secret, token, API key, ...). Matching ignores case and the
// separators '-', '_' and '.', so "API-Key", "api_key" and "apiKey" all match.
func IsSensitiveKey(k string) bool {
	n := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(k))
	for _, f := range sensitiveFragments {
		if strings.Contains(n, f) {
			return true
		}
	}
	return false
}

// Redact returns a deep copy of m in which the values of sensitive keys
// (see IsSensitiveKey) are replaced with Redacted. Nested maps and slices are
// walked. A nil map yields nil.
func Redact(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			out[k] = Redacted
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return Redact(t)
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, s := range t {
			m[k] = s
		}
		return Redact(m)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redactValue(x)
		}
		return out
	default:
		return v
	}
}
