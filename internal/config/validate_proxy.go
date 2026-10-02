package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// validateProxy checks the edge-proxy plane (network/sip.public/
// sip.private/sip.upstream/rtp.public/rtp.private/webrtc). It is
// a no-op for a trunk-only config apart from rejecting half-written
// sections: a public listener, or a media plane configured
// WITHOUT an upstream is a mistake worth naming, not a silent no-op.
//
// fail is validate's error collector, so every problem in the file is
// reported in one pass.
func (c *Config) validateProxy(fail failFunc) {
	if !c.ProxyEnabled() {
		if c.proxyPartlyConfigured() {
			fail("sip.upstream: required to enable the edge proxy — set sip.upstream.address or sip.upstreams.nodes; sip.public/sip.private/rtp.public/rtp.private/webrtc are configured but there is no upstream to proxy to")
		}
		return
	}

	// A trunk listener with no peers can only drop traffic: the trunk
	// plane identifies every inbound request by matching its source
	// against a peer's allowed_ips, so with no peers configured the
	// listener is dead weight. Without the edge proxy this is already
	// rejected ("peers: at least one peer required"); with it, the
	// listener would otherwise bind silently and serve nothing.
	if len(c.Peers) == 0 && (len(c.Listen.SIP) > 0 || c.SIP.BindIP != "") {
		fail("listen.sip/sip.bind_ip: configured with no peers — the trunk plane identifies callers by peer allowed_ips, so this listener could only drop traffic. Remove it, or add the peers it is for.")
	}

	c.validateUpstreams(fail)
	c.validatePlane("network.public", c.Network.Public, fail)
	c.validatePlane("network.private", c.Network.Private, fail)
	c.validatePublicListeners(fail)
	c.validateCarrierSources(fail)
	c.validatePrivateSIP(fail)
	c.validateMediaPlanes(fail)
	c.validatePoolOverlap(fail)
	c.validateWebRTC(fail)
}

// proxyPartlyConfigured reports whether any edge-only section was written.
func (c *Config) proxyPartlyConfigured() bool {
	ups := c.SIP.Upstreams
	upsSet := len(ups.Nodes) > 0 || ups.Algorithm != "" || ups.Cooldown != 0
	return len(c.PublicSIPListeners()) > 0 || c.RTP.Public.configured() || c.RTP.Private.configured() ||
		c.WebRTC.Enabled || !c.SIP.Private.Bind.IsZero() || upsSet ||
		len(c.SIP.Public.CarrierSources) > 0
}

// validateUpstreams checks the upstream in either shape.
func (c *Config) validateUpstreams(fail failFunc) {
	// Two mutually exclusive shapes: the v1 alias
	// (sip.upstream.address) and the multi-switch pool (sip.upstreams.nodes).
	// The alias converges on the pool at topology build time as node
	// "default", so the runtime never knows which shape produced it — but
	// writing both is a mistake worth naming, not a merge to guess at.
	ups := c.SIP.Upstreams
	if c.SIP.Upstream.Address != "" && len(ups.Nodes) > 0 {
		fail("sip.upstreams: sip.upstream.address and sip.upstreams.nodes are mutually exclusive — use the single-upstream alias or the multi-switch pool, not both")
	}
	if c.SIP.Upstream.Address != "" {
		checkIPPort(fail, "sip.upstream.address", c.SIP.Upstream.Address)
		// Deliberately narrow: §2 of the spec scopes the private/upstream
		// transport to UDP for this phase. Reject anything else loudly rather
		// than binding a transport the forwarding path can't route responses
		// back through.
		checkUDPOnly(fail, "sip.upstream.transport", c.SIP.Upstream.Transport)
	}
	if len(ups.Nodes) > 0 {
		// The algorithm field is a forward-compatibility seam: exactly one
		// value is implemented, so anything else is a config error rather
		// than a silent fallback to hashing. Each node is checked like the
		// alias — literal IP:port, UDP only.
		if ups.Algorithm != "hash-user" {
			fail("sip.upstreams.algorithm: only \"hash-user\" is supported, got %q", ups.Algorithm)
		}
		for _, name := range sortedKeys(ups.Nodes) {
			n := ups.Nodes[name]
			label := "sip.upstreams.nodes." + name
			if n == nil || n.Address == "" {
				fail("%s.address: required", label)
				continue
			}
			checkIPPort(fail, label+".address", n.Address)
			// Same reasoning as the alias transport: the private leg is UDP in
			// this phase, and the forwarding path has no way to route a
			// TCP/TLS response back to the right transaction.
			checkUDPOnly(fail, label+".transport", n.Transport)
		}
	}
	if ups.Cooldown < 0 {
		// Zero means "use the default", so a
		// negative value is an operator mistake to name, not to default
		// away.
		fail("sip.upstreams.cooldown: must not be negative, got %v", ups.Cooldown.Std())
	}
}

// validatePublicListeners checks the enabled public listeners. Their binds
// are never empty here: proxyWithDefaults gives every enabled listener a
// default bind (audit P2-CFG-010), and socket collisions across every
// plane are validateSockets' job.
func (c *Config) validatePublicListeners(fail failFunc) {
	listeners := c.PublicSIPListeners()
	if len(listeners) == 0 {
		fail("sip.public: at least one of udp/ws/wss must be enabled when the edge proxy is on")
	}
	for _, l := range listeners {
		label := "sip.public." + l.Transport
		if _, err := netip.ParseAddr(l.Bind.Host); err != nil {
			fail("%s.bind: %q is not a valid IP", label, l.Bind.Host)
		}
		if l.Transport == "wss" {
			checkFilePair(fail, "sip.public.wss", "cert_file", l.CertFile, "key_file", l.KeyFile)
		}
	}
	if !c.PublicAdvertisedIP().IsValid() {
		fail("network.public.advertised_ip: required — the public bind address is unspecified/unset, so Contact, Via and SDP would have no routable address to advertise")
	}
	if !c.PrivateAdvertisedIP().IsValid() {
		fail("network.private.advertised_ip: required — the private bind address is unspecified/unset, so FreeSWITCH would have no routable address to reach the SBC on")
	}
}

// validateCarrierSources checks and compiles sip.public.carrier_sources with
// the rules of a trunk peer's allowed_ips (allowedPrefix): a bare IP is its
// full-length prefix, a CIDR is normalised, an IPv4-mapped entry becomes the
// IPv4 prefix it maps, and anything wider than /8 (IPv4) or /32 (IPv6) —
// 0.0.0.0/0 and ::/0 included — is refused. The list is a trust boundary for
// unauthenticated INVITEs into FreeSWITCH, so a catch-all would switch the
// admission check off. An empty or absent list is valid.
func (c *Config) validateCarrierSources(fail failFunc) {
	c.SIP.Public.carrierNets = nil
	for _, s := range c.SIP.Public.CarrierSources {
		if pfx, ok := allowedPrefix(fail, "sip.public.carrier_sources", s); ok {
			c.SIP.Public.carrierNets = append(c.SIP.Public.carrierNets, pfx)
		}
	}
}

// validatePrivateSIP checks the private SIP socket. Its bind is always set
// here: proxyWithDefaults defaults it whenever the proxy is on (audit
// P2-CFG-010).
func (c *Config) validatePrivateSIP(fail failFunc) {
	if _, err := netip.ParseAddr(c.SIP.Private.Bind.Host); err != nil {
		fail("sip.private.bind: %q is not a valid IP", c.SIP.Private.Bind.Host)
	}
	checkAdvertisedIP(fail, "sip.private.advertised_ip", c.SIP.Private.AdvertisedIP, "FreeSWITCH could not route to it")
	checkPort(fail, "sip.private.advertised_port", c.SIP.Private.AdvertisedPort)
}

// validateMediaPlanes checks rtp.public and rtp.private.
func (c *Config) validateMediaPlanes(fail failFunc) {
	c.validateRTPPlane("rtp.public", c.RTP.Public, fail)
	c.validateRTPPlane("rtp.private", c.RTP.Private, fail)
	if !c.RTP.Public.configured() {
		fail("rtp.public: port_min/port_max required when the edge proxy is on")
	}
	if !c.RTP.Private.configured() {
		fail("rtp.private: port_min/port_max required when the edge proxy is on")
	}
	if !c.PublicRTPAdvertisedIP().IsValid() {
		fail("rtp.public.advertised_ip: required — no advertised public media address, so SDP toward phones/browsers would be unroutable")
	}
	if !c.PrivateRTPAdvertisedIP().IsValid() {
		fail("rtp.private.advertised_ip: required — no advertised private media address, so SDP toward FreeSWITCH would be unroutable")
	}
}

// validatePoolOverlap rejects media pools that could hand out the same
// port. Each pool tracks its own in-use set, so the second bind merely
// fails and the call is rejected — a silent capacity cliff. The trunk
// plane's own range is included: with a shared bind address it draws from
// the same port space.
func (c *Config) validatePoolOverlap(fail failFunc) {
	type namedRange struct {
		label string
		bind  string
		r     PortRange
	}
	ranges := []namedRange{
		{"rtp.public", c.RTP.Public.BindIP, c.RTP.Public.Range()},
		{"rtp.private", c.RTP.Private.BindIP, c.RTP.Private.Range()},
	}
	if tr := c.RTPPortRange(); tr != (PortRange{}) && len(c.Peers) > 0 {
		ranges = append(ranges, namedRange{"the trunk media range (rtp.port_min/port_max or listen.media.port_range)", c.RTP.BindIP, tr})
	}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			a, b := ranges[i], ranges[j]
			if a.r == (PortRange{}) || b.r == (PortRange{}) || !bindsCanCollide(a.bind, b.bind) {
				continue
			}
			if a.r.Min <= b.r.Max && b.r.Min <= a.r.Max {
				fail("%s and %s overlap on %d-%d: each media pool needs its own port range",
					a.label, b.label, maxU16(a.r.Min, b.r.Min), minU16(a.r.Max, b.r.Max))
			}
		}
	}
}

// validateWebRTC checks the browser media leg.
func (c *Config) validateWebRTC(fail failFunc) {
	if !c.WebRTC.Enabled {
		return
	}
	if c.WebRTC.ICEMode != "lite" {
		fail("webrtc.ice_mode: only \"lite\" is supported, got %q", c.WebRTC.ICEMode)
	}
	if c.WebRTC.RTCPMux != nil && !*c.WebRTC.RTCPMux {
		fail("webrtc.rtcp_mux: must be true — FreeSBC allocates one ICE component per session and cannot serve a non-muxed browser leg")
	}
	if !c.SIP.Public.WS.Enabled && !c.SIP.Public.WSS.Enabled {
		fail("webrtc.enabled: requires sip.public.ws or sip.public.wss — a browser has no other way to signal")
	}
}

// boundSocket is one listening socket the process will bind at startup.
type boundSocket struct {
	label string // config key, for the error
	proto string // "udp" or "tcp"
	host  string
	port  int
}

// validateSockets rejects two listeners that would bind the same socket, on
// either plane or the admin API: `run` would fail with "address already in
// use", so `check` must too (audit P2-CFG-004). tcp, tls, ws and wss all
// listen on TCP; a wildcard bind collides with every address on its port.
func (c *Config) validateSockets(fail failFunc) {
	var socks []boundSocket
	if c.SIP.BindIP != "" {
		socks = append(socks, boundSocket{"sip.bind_ip", sockProto(c.SIP.Transport), c.SIP.BindIP, c.SIP.BindPort})
	}
	for i, l := range c.Listen.SIP {
		socks = append(socks, boundSocket{fmt.Sprintf("listen.sip[%d]", i), sockProto(l.Transport), l.Host, l.Port})
	}
	if c.ProxyEnabled() {
		for _, l := range c.PublicSIPListeners() {
			socks = append(socks, boundSocket{"sip.public." + l.Transport + ".bind", sockProto(l.Transport), l.Bind.Host, l.Bind.Port})
		}
		b := c.SIP.Private.Bind
		socks = append(socks, boundSocket{"sip.private.bind", "udp", b.Host, b.Port})
	}
	if c.Admin != nil {
		if ap, err := netip.ParseAddrPort(c.Admin.Listen); err == nil {
			socks = append(socks, boundSocket{"admin.listen", "tcp", ap.Addr().String(), int(ap.Port())})
		}
	}
	for i := 1; i < len(socks); i++ {
		for _, prev := range socks[:i] {
			s := socks[i]
			if s.proto == prev.proto && s.port == prev.port && hostsCollide(s.host, prev.host) {
				fail("%s: %s/%s already bound by %s", s.label, s.proto, net.JoinHostPort(s.host, strconv.Itoa(s.port)), prev.label)
				break
			}
		}
	}
}

// hostsCollide reports whether two listeners on one protocol and port bind
// overlapping addresses: an empty or unspecified host is every interface
// and collides with anything; two IPs collide only when equal. A hostname
// (legal in listen.sip) binds whatever it resolves to at startup, which
// validation cannot know, so it collides only with the same name.
func hostsCollide(a, b string) bool {
	wildcard := func(h string) bool {
		ip, err := netip.ParseAddr(h)
		return h == "" || (err == nil && ip.IsUnspecified())
	}
	if wildcard(a) || wildcard(b) {
		return true
	}
	ia, errA := netip.ParseAddr(a)
	ib, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ia == ib
}

// sockProto maps a SIP transport to the socket protocol it listens on.
func sockProto(transport string) string {
	if transport == "udp" {
		return "udp"
	}
	return "tcp"
}

// sortedKeys returns m's keys in order, so errors come out stable.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *Config) validatePlane(label string, p NetworkPlane, fail failFunc) {
	checkIP(fail, label+".bind_ip", p.BindIP)
	checkAdvertisedIP(fail, label+".advertised_ip", p.AdvertisedIP, "advertising it would blackhole signaling and media")
}

func (c *Config) validateRTPPlane(label string, p RTPPlaneConfig, fail failFunc) {
	if !p.configured() {
		return
	}
	checkIP(fail, label+".bind_ip", p.BindIP)
	checkAdvertisedIP(fail, label+".advertised_ip", p.AdvertisedIP, "SDP would blackhole media")
	if (p.PortMin == 0) != (p.PortMax == 0) {
		fail("%s: port_min and port_max must be set together", label)
		return
	}
	if p.PortMin == 0 {
		fail("%s: port_min/port_max required", label)
		return
	}
	checkPortRange(fail, label, label, "session", p.PortMin, p.PortMax)
	// An edge session binds one pair per plane; a range such as
	// 30001-30002 passes min < max yet holds none (audit P2-CFG-009).
	if p.PortMin < p.PortMax && rtpPairs(p.PortMin, p.PortMax) < 1 {
		fail("%s: %d-%d holds no RTP/RTCP pair (RTP on an even port, RTCP on RTP+1) — widen it", label, p.PortMin, p.PortMax)
	}
}

// checkIPPort fails unless address is a literal "IP:port" with a port in
// 1-65535. Every edge-plane address is one: the edge plane does no DNS
// (edge/topology.go parseEndpoint), so `check` rejects a hostname exactly
// as `run` would (audit P2-CFG-004). label is the full config key.
func checkIPPort(fail failFunc, label, address string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		fail("%s: %q is not \"host:port\"", label, address)
		return
	}
	if host == "" {
		fail("%s: host required", label)
	} else if _, err := netip.ParseAddr(host); err != nil {
		fail("%s: %q is not a literal IP — the edge plane does no DNS", label, host)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		fail("%s: bad port in %q", label, address)
	}
}

// checkUDPOnly rejects every transport but UDP. Both the private/upstream
// leg and the carrier leg are UDP-only in this phase: the forwarding path
// has no way to route a TCP/TLS response back to the right transaction.
func checkUDPOnly(fail failFunc, label, transport string) {
	if transport != "udp" {
		fail("%s: only \"udp\" is supported, got %q", label, transport)
	}
}

// bindsCanCollide reports whether two pools' bind addresses draw from the
// same host port space. An empty or unspecified bind means "every
// interface", which collides with everything; two different specific
// addresses do not.
func bindsCanCollide(a, b string) bool {
	wildcard := func(s string) bool {
		if s == "" {
			return true
		}
		ip, err := netip.ParseAddr(s)
		return err != nil || ip.IsUnspecified()
	}
	if wildcard(a) || wildcard(b) {
		return true
	}
	return a == b
}

func maxU16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

func minU16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
