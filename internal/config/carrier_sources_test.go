package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// withCarrierSources adds a sip.public.carrier_sources line to proxyYAML.
func withCarrierSources(list string) string {
	return strings.Replace(proxyYAML, "  public:\n    udp:\n", "  public:\n    carrier_sources: "+list+"\n    udp:\n", 1)
}

// sip.public.carrier_sources is validated and compiled like a trunk peer's
// allowed_ips: a bare IP is a host prefix, a CIDR is normalised, an
// IPv4-mapped entry becomes its IPv4 prefix, and a catch-all or malformed
// entry is refused. Absent or empty is valid.
func TestCarrierSourcesParse(t *testing.T) {
	c := mustParseProxy(t, withCarrierSources(`["198.51.100.7", "203.0.113.9/24", "::ffff:192.0.2.0/120", "2001:db8::/48"]`))
	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/48"),
	}
	if got := c.SIP.Public.CarrierNets(); !slices.Equal(got, want) {
		t.Errorf("CarrierNets = %v, want %v", got, want)
	}

	for _, list := range []string{"", "[]"} {
		src := proxyYAML
		if list != "" {
			src = withCarrierSources(list)
		}
		if c := mustParseProxy(t, src); len(c.SIP.Public.CarrierNets()) != 0 {
			t.Errorf("carrier_sources %q: CarrierNets = %v, want none", list, c.SIP.Public.CarrierNets())
		}
	}

	for entry, wantErr := range map[string]string{
		"0.0.0.0/0":         `sip.public.carrier_sources: "0.0.0.0/0" is wider than /8 (T-11 width cap)`,
		"::/0":              `sip.public.carrier_sources: "::/0" is wider than /32 (T-11 width cap)`,
		"10.0.0.0/7":        `sip.public.carrier_sources: "10.0.0.0/7" is wider than /8 (T-11 width cap)`,
		"carrier.example":   `sip.public.carrier_sources: "carrier.example" is neither a CIDR nor an IP`,
		"198.51.100.0/33":   `sip.public.carrier_sources: "198.51.100.0/33" is neither a CIDR nor an IP`,
		"::ffff:10.0.0.0/8": `sip.public.carrier_sources: "::ffff:10.0.0.0/8" mixes IPv4-mapped and native IPv6 addresses; write the IPv4 prefix instead`,
	} {
		_, err := Parse([]byte(withCarrierSources(`["` + entry + `"]`)))
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("carrier_sources [%s]: err = %v, want %q", entry, err, wantErr)
		}
	}
}

// carrier_sources without an edge plane is a half-written edge section and
// is named as such, not silently ignored.
func TestCarrierSourcesWithoutUpstreamRejected(t *testing.T) {
	src := minimalYAML + "sip:\n  public:\n    carrier_sources: [198.51.100.7]\n"
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "sip.upstream: required to enable the edge proxy") {
		t.Fatalf("err = %v, want the missing-upstream error", err)
	}
}

// Parameterising allowedPrefix's label must leave the trunk's allowed_ips
// messages byte-for-byte as they were.
func TestAllowedIPsMessagesUnchanged(t *testing.T) {
	for entry, wantErr := range map[string]string{
		"0.0.0.0/0":         `peers.pbx: allowed_ips: "0.0.0.0/0" is wider than /8 (T-11 width cap)`,
		"bogus":             `peers.pbx: allowed_ips: "bogus" is neither a CIDR nor an IP`,
		"::ffff:10.0.0.0/8": `peers.pbx: allowed_ips: "::ffff:10.0.0.0/8" mixes IPv4-mapped and native IPv6 addresses; write the IPv4 prefix instead`,
	} {
		src := strings.Replace(minimalYAML, "allowed_ips: [10.0.0.0/8]", `allowed_ips: ["`+entry+`"]`, 1)
		_, err := Parse([]byte(src))
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("allowed_ips [%s]: err = %v, want %q", entry, err, wantErr)
		}
	}
}

// carrier_sources lives under sip.public, which is restart-only (the edge
// builds its admission set once, in edge.New): a reload that edits it is
// reported under the existing sip.public entry, not a new one.
func TestRestartOnlyReportsCarrierSources(t *testing.T) {
	running := mustParseProxy(t, proxyYAML)
	next := mustParseProxy(t, withCarrierSources("[198.51.100.7]"))
	if got, want := RestartOnlyChanges(running, next), []string{"sip.public"}; !slices.Equal(got, want) {
		t.Errorf("RestartOnlyChanges = %q, want %q", got, want)
	}
	again := mustParseProxy(t, withCarrierSources("[198.51.100.7]"))
	if got := RestartOnlyChanges(next, again); len(got) != 0 {
		t.Errorf("identical carrier_sources reported as a change: %q", got)
	}
}
