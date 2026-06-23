// Package conf parses a minimal flat YAML config (key: value per line).
//
// Pure stdlib — no third-party YAML dependency (keeps the engine zero-deps).
// Supports: "key: value" pairs, # comments (full-line and inline), and
// optionally double-quoted values. Nesting/lists are intentionally not
// supported — rctd's config is flat.
package conf

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseFlat returns the top-level key/value pairs from flat YAML.
func ParseFlat(data []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if strings.HasPrefix(val, "\"") {
			// quoted: take content up to the closing quote
			if j := strings.IndexByte(val[1:], '"'); j >= 0 {
				val = val[1 : 1+j]
			} else {
				val = strings.Trim(val, "\"")
			}
		} else if c := strings.Index(val, " #"); c >= 0 {
			// strip inline comment on unquoted values
			val = strings.TrimSpace(val[:c])
		}
		if key != "" {
			m[key] = val
		}
	}
	return m
}
