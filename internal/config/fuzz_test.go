package config

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

// auditKnownPanicSites are crash signatures already reported. With
// AUDIT_FUZZ_SKIP_KNOWN=1 the fuzzer ignores them so it can look for new
// ones; without it every panic fails the target.
var auditKnownPanicSites = []string{
	"goccy/go-yaml", // P3-CORE-001
}

// FuzzAuditConfigParse: Parse on arbitrary YAML must return an error,
// never panic (crash hunt; P2-CFG-001, P3-CORE-001).
func FuzzAuditConfigParse(f *testing.F) {
	skipKnown := os.Getenv("AUDIT_FUZZ_SKIP_KNOWN") == "1"
	f.Add([]byte(minimalYAML))
	f.Add([]byte("public: { ip: 1.2.3.4 }\nprivate: { ip: 10.0.0.1 }\nedge:\n  switch: [10.0.0.2:5060]\n  listen: { udp: 5060, wss: 443 }\n  carriers: { a: sip.example.com, b: \"[::1]:5070\" }\n  carrier_sources: [10.0.0.0/8]\ntls: { cert: a, key: b }\nadmin: { listen: 127.0.0.1:8080, password_hash: x }\n"))
	f.Add([]byte("peers: {}\nlisten:\n  sip: [udp://0.0.0.0:5060]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if skipKnown {
			defer func() {
				if r := recover(); r != nil {
					stack := string(debug.Stack())
					for _, site := range auditKnownPanicSites {
						if strings.Contains(stack, site) {
							return
						}
					}
					panic(r)
				}
			}()
		}
		_, _ = Parse(data)
	})
}
