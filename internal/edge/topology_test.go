package edge

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

const topoYAML = `
public: {ip: 203.0.113.7, bind: 172.31.5.10}
private: {ip: 10.77.0.2}
edge:
  switch: [10.77.0.10:5060]
  listen: {udp: 16060, ws: 18080}
`

func buildTestTopology(t *testing.T, yaml string) *topology {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return buildTopology(cfg, cfg.PrivateAddr())
}

func testTopology(t *testing.T) *topology { return buildTestTopology(t, topoYAML) }

func TestTopologySides(t *testing.T) {
	topo := testTopology(t)
	udp, ok := topo.publicSide("udp")
	if !ok {
		t.Fatal("no udp public side")
	}
	if udp.advIP.String() != "203.0.113.7" || udp.advPort != 16060 {
		t.Errorf("udp side = %v:%d", udp.advIP, udp.advPort)
	}
	// The socket binds public.bind while public.ip is what is advertised.
	if udp.laddr.Port != 16060 || udp.laddr.IP.String() != "172.31.5.10" {
		t.Errorf("udp laddr = %+v, want 172.31.5.10:16060", udp.laddr)
	}
	ws, ok := topo.publicSide("ws")
	if !ok {
		t.Fatal("no ws public side")
	}
	// A WebSocket has no outbound socket to pin: the connection is found
	// by the client's remote address instead.
	if ws.laddr.IP != nil {
		t.Errorf("ws side pinned a local socket: %+v", ws.laddr)
	}
	if _, ok := topo.publicSide("wss"); ok {
		t.Error("wss side exists though it is not enabled")
	}
	if topo.private.advIP.String() != "10.77.0.2" || topo.private.advPort != 5060 || topo.private.laddr.Port != 5060 {
		t.Errorf("private side = %v:%d (laddr %+v), want 10.77.0.2:5060", topo.private.advIP, topo.private.advPort, topo.private.laddr)
	}
	if topo.publicMediaIP.String() != "203.0.113.7" || topo.privateMediaIP.String() != "10.77.0.2" {
		t.Errorf("media addresses = %v / %v", topo.publicMediaIP, topo.privateMediaIP)
	}
}

func TestSideURIAndRecordRoute(t *testing.T) {
	topo := testTopology(t)
	ws, _ := topo.publicSide("ws")
	u := ws.uri()
	if !strings.Contains(u.String(), "transport=ws") {
		t.Errorf("ws contact URI missing transport: %s", u.String())
	}
	rr := ws.recordRoute().Value()
	if !strings.Contains(rr, "lr") || !strings.Contains(rr, "transport=ws") {
		t.Errorf("ws Record-Route = %s", rr)
	}
	udp, _ := topo.publicSide("udp")
	udpURI := udp.uri()
	if strings.Contains(udpURI.String(), "transport") {
		t.Errorf("udp contact URI should not name a transport: %s", udpURI.String())
	}
	// rport is requested on UDP (it is what makes NAT traversal work) and
	// meaningless on a WebSocket.
	if _, ok := udp.via("z9hG4bKtest").Params.Get("rport"); !ok {
		t.Error("udp Via missing rport")
	}
	if _, ok := ws.via("z9hG4bKtest").Params.Get("rport"); ok {
		t.Error("ws Via should not request rport")
	}
}

func TestTopologyIsSelf(t *testing.T) {
	topo := testTopology(t)
	for _, u := range []sip.Uri{
		{Host: "203.0.113.7", Port: 16060},
		{Host: "203.0.113.7", Port: 18080},
		{Host: "10.77.0.2", Port: 5060},
	} {
		if !topo.isSelf(u) {
			t.Errorf("%v not recognised as self", u)
		}
	}
	for _, u := range []sip.Uri{
		{Host: "203.0.113.7", Port: 5060},  // right host, wrong port
		{Host: "203.0.113.8", Port: 16060}, // wrong host
		{Host: "10.77.0.2", Port: 16060},   // private IP on a public port
		{Host: "172.31.5.10", Port: 16060}, // the bind address is not advertised
		{Host: "example.com", Port: 16060}, // not an IP at all
		{Host: "10.77.0.10", Port: 5060},   // the upstream, not us
	} {
		if topo.isSelf(u) {
			t.Errorf("%v wrongly recognised as self", u)
		}
	}
}

// multiSwitchYAML is topoYAML with a three-node pool: enough nodes for the
// hash to spread over and for a cooled node to have alternatives.
var multiSwitchYAML = strings.Replace(topoYAML, "[10.77.0.10:5060]",
	"[10.77.0.10:5060, 10.77.0.11:5060, 10.77.0.12:5060]", 1)

// The three node names of multiSwitchYAML, in sorted (= pool) order.
const (
	nodeA = "10.77.0.10:5060"
	nodeB = "10.77.0.11:5060"
	nodeC = "10.77.0.12:5060"
)

func testMultiTopology(t *testing.T) *topology { return buildTestTopology(t, multiSwitchYAML) }

func TestTopologyFromUpstream(t *testing.T) {
	topo := testTopology(t)
	if !topo.fromUpstream(netip.MustParseAddr("10.77.0.10")) {
		t.Error("upstream address not recognised")
	}
	// The port is deliberately not compared: FreeSWITCH may source from an
	// ephemeral port while listening on its configured one.
	if !topo.fromUpstream(netip.MustParseAddr("::ffff:10.77.0.10").Unmap()) {
		t.Error("IPv4-mapped upstream address not recognised")
	}
	if topo.fromUpstream(netip.MustParseAddr("203.0.113.99")) {
		t.Error("a public address was treated as upstream")
	}

	// The trust decision is a set over the WHOLE pool: any switch in it may
	// source a request, and a node that is not in it is not trusted.
	multi := testMultiTopology(t)
	for _, ip := range []string{"10.77.0.10", "10.77.0.11", "10.77.0.12", "::ffff:10.77.0.12"} {
		if !multi.fromUpstream(netip.MustParseAddr(ip)) {
			t.Errorf("pool address %s not recognised", ip)
		}
	}
	if multi.fromUpstream(netip.MustParseAddr("10.77.0.13")) {
		t.Error("an address outside the pool was treated as upstream")
	}
}

// A single edge.switch entry is a one-node pool named by its "IP:port": the
// hash degenerates trivially (one node is always index 0).
func TestTopologySingleSwitch(t *testing.T) {
	topo := testTopology(t)
	if len(topo.upstreams) != 1 || len(topo.upstreamNames) != 1 || topo.upstreamNames[0] != nodeA {
		t.Fatalf("upstreams = %+v names = %v, want exactly [%s]", topo.upstreams, topo.upstreamNames, nodeA)
	}
	entry := topo.upstreamEntryFor(nodeA)
	if got := entry.addr.String(); got != nodeA {
		t.Errorf("entry addr = %s", got)
	}
	if entry.host != nodeA {
		t.Errorf("entry host = %q", entry.host)
	}
	// The dial order for ANY user is that one node.
	for _, user := range []string{"1001", "alice", ""} {
		if order := topo.upstreamDialOrder(user, alwaysAvailable); len(order) != 1 || order[0] != nodeA {
			t.Errorf("dial order for %q = %v, want [%s]", user, order, nodeA)
		}
	}
}

// The pool is resolved per node, with the names sorted once at build time
// — the hash pool and the failover order must never depend on Go's map
// iteration order.
func TestTopologyMultiSwitch(t *testing.T) {
	topo := testMultiTopology(t)
	want := []string{nodeA, nodeB, nodeC}
	if !equalStrings(topo.upstreamNames, want) {
		t.Fatalf("names = %v, want %v", topo.upstreamNames, want)
	}
	for _, name := range want {
		if entry := topo.upstreamEntryFor(name); entry.host != name || entry.addr.String() != name {
			t.Errorf("node %s = %+v", name, entry)
		}
	}
}

// Each node carries the port carrier traffic is delivered to: the node's
// own switch port, or edge.switch_carrier_port when set.
func TestTopologyCarrierPort(t *testing.T) {
	topo := testMultiTopology(t)
	for _, name := range topo.upstreamNames {
		if got := topo.upstreamEntryFor(name).carrierAddr().String(); got != name {
			t.Errorf("default carrier address of %s = %s, want its own switch port", name, got)
		}
	}
	topo = buildTestTopology(t, strings.Replace(multiSwitchYAML, "edge:\n", "edge:\n  switch_carrier_port: 5080\n", 1))
	for _, name := range topo.upstreamNames {
		e := topo.upstreamEntryFor(name)
		if got := e.carrierAddr().String(); got != e.addr.Addr().String()+":5080" {
			t.Errorf("carrier address of %s = %s, want port 5080", name, got)
		}
		if e.addr.Port() != 5060 {
			t.Errorf("switch_carrier_port changed the client port of %s: %v", name, e.addr)
		}
	}
}

// The carrier-source set is edge.carrier_sources plus the literal-IP
// carriers; a DNS-name carrier contributes nothing without resolution.
func TestTopologyCarrierSources(t *testing.T) {
	topo := buildTestTopology(t, strings.Replace(topoYAML, "  listen: {udp: 16060, ws: 18080}\n",
		"  listen: {udp: 16060, ws: 18080}\n  carrier_sources: [198.51.100.0/28]\n  carriers: {a: 223.76.90.4:16060, b: sip.carrier-b.example}\n", 1))
	for ip, want := range map[string]bool{
		"198.51.100.9": true, "223.76.90.4": true, "223.76.90.5": false, "10.77.0.10": false,
	} {
		if got := topo.isCarrierSource(netip.MustParseAddr(ip)); got != want {
			t.Errorf("isCarrierSource(%s) = %v, want %v", ip, got, want)
		}
	}
}

// hashUpstreamUser is the selection contract: FNV-1a 64 over the LOWER-CASED
// user. The fixed vectors pin the algorithm (changing it silently would
// remap every user), the case check pins the lower-casing (a phone that
// registers as "Bob" and calls as "bob" must land on one switch), and the
// empty string pins that a missing user part is still a deterministic input.
func TestHashUpstreamUser(t *testing.T) {
	vectors := []struct {
		user string
		want uint64
	}{
		{"1001", 973458052660218839},
		{"1002", 973459152171847050},
		{"alice", 5803779529149266183},
		{"Bob", 21748447695211092},
		{"bob", 21748447695211092},
		{"", 14695981039346656037}, // FNV-1a 64 offset basis
	}
	for _, v := range vectors {
		if got := hashUpstreamUser(v.user); got != v.want {
			t.Errorf("hashUpstreamUser(%q) = %d, want %d", v.user, got, v.want)
		}
	}
	if hashUpstreamUser("Bob") != hashUpstreamUser("bob") {
		t.Error("hash is case-sensitive: Bob and bob must agree")
	}
}

// upstreamDialOrder is the failover plan: the hash-chosen node first, the
// rest of the available pool in rotation from it, and cooled nodes only
// after every available one — and excluded from the hash pool entirely
// (D6), so a sick node stops receiving its share of the users.
func TestUpstreamDialOrder(t *testing.T) {
	topo := testMultiTopology(t)
	all := func(string) bool { return true }

	// Determinism: the same user always yields the same order, and the
	// order is a permutation of the pool.
	first := topo.upstreamDialOrder("1001", all)
	if len(first) != 3 {
		t.Fatalf("order = %v, want 3 nodes", first)
	}
	if again := topo.upstreamDialOrder("1001", all); !equalStrings(first, again) {
		t.Errorf("order not deterministic: %v then %v", first, again)
	}
	seen := map[string]bool{}
	for _, name := range first {
		if seen[name] {
			t.Fatalf("order repeats %s: %v", name, first)
		}
		seen[name] = true
	}
	// The head is the pure hash of the user modulo the pool, exactly as
	// selectUpstream promises.
	wantHead := topo.upstreamNames[hashUpstreamUser("1001")%3]
	if first[0] != wantHead {
		t.Errorf("head = %s, want %s", first[0], wantHead)
	}
	// Rotation: the order is the sorted pool rotated to start at the head.
	wantOrder := append(append([]string{}, topo.upstreamNames[hashUpstreamUser("1001")%3:]...),
		topo.upstreamNames[:hashUpstreamUser("1001")%3]...)
	if !equalStrings(first, wantOrder) {
		t.Errorf("order = %v, want rotation %v", first, wantOrder)
	}

	// Spread: over the three pool sizes at least two distinct heads appear
	// (a degenerate hash would pin everyone to one switch).
	heads := map[string]bool{}
	for _, user := range []string{"1001", "1002", "1003", "1004", "1005", "1006", "1007", "1008"} {
		heads[topo.upstreamDialOrder(user, all)[0]] = true
	}
	if len(heads) < 2 {
		t.Errorf("every user hashed to one node: %v", heads)
	}

	// Cooled nodes: node A cooling drops it from the hash pool AND puts it
	// last, so a user who hashes to fs-a now starts elsewhere and only
	// reaches fs-a if both alternatives fail.
	coolingA := func(name string) bool { return name != nodeA }
	order := topo.upstreamDialOrder("1001", coolingA)
	if order[0] == nodeA {
		t.Errorf("cooled node dialed first: %v", order)
	}
	if order[len(order)-1] != nodeA {
		t.Errorf("cooled node not last: %v", order)
	}
	// A user whose hash WOULD pick fs-a (over the two-node available pool)
	// is remapped onto the available pool entirely — the cooled node cannot
	// win by modulo.
	for _, user := range []string{"1001", "1002", "alice", "u0", "u1", "u2"} {
		if got := topo.upstreamDialOrder(user, coolingA); got[0] == nodeA {
			t.Errorf("user %q still hashed to a cooled node: %v", user, got)
		}
	}

	// All cooled: dial the full pool rather than nothing — a cooldown is a
	// suspicion, not a verdict. The order is the user's normal hash order
	// (the pool is the same), not the sorted order.
	none := func(string) bool { return false }
	if order := topo.upstreamDialOrder("1001", none); !equalStrings(order, first) {
		t.Errorf("all-cooled order = %v, want the full-pool hash order %v", order, first)
	}
}

func TestSelectUpstream(t *testing.T) {
	topo := testMultiTopology(t)
	all := func(string) bool { return true }
	name, entry, ok := topo.selectUpstream("1001", all)
	if !ok {
		t.Fatal("selectUpstream found no node")
	}
	if name != topo.upstreamNames[hashUpstreamUser("1001")%3] {
		t.Errorf("selected %s, want the hash head", name)
	}
	if entry.host == "" || entry.addr.Addr().String() == "" {
		t.Errorf("entry not resolved: %+v", entry)
	}
	// Selection skips a cooled node in favour of its alternatives.
	coolingA := func(n string) bool { return n != nodeA }
	for i := 0; i < 3; i++ {
		if name, _, _ := topo.selectUpstream("1001", coolingA); name == nodeA {
			t.Errorf("selected a cooled node")
		}
	}
	// An empty pool is the only failure mode (impossible on a validated
	// config, but the caller must not panic on it).
	empty := &topology{}
	if _, _, ok := empty.selectUpstream("1001", all); ok {
		t.Error("empty topology reported a selection")
	}
}

// alwaysAvailable is the availability oracle of a topology with nothing
// cooling.
func alwaysAvailable(string) bool { return true }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The read filter's private-listener test: the address comparison treats a
// wildcard bind as any host on its port, and a read on another transport
// never matches the UDP private bind.
func TestSameListener(t *testing.T) {
	cases := []struct {
		tr, a, b string
		want     bool
	}{
		{"udp", "10.0.0.1:5060", "10.0.0.1:5060", true},
		{"udp", "0.0.0.0:5060", "10.0.0.1:5060", true}, // wildcard listener
		{"udp", "10.0.0.1:5060", "0.0.0.0:5060", true},
		{"udp", "10.0.0.1:5060", "10.0.0.2:5060", false},
		{"udp", "0.0.0.0:5060", "10.0.0.1:5061", false}, // different port
		{"ws", "10.0.0.1:5060", "0.0.0.0:5060", false},  // different transport
	}
	for _, c := range cases {
		if got := fsip.SameListener(c.tr, c.a, "udp", c.b); got != c.want {
			t.Errorf("fsip.SameListener(%s %q, udp %q) = %v, want %v", c.tr, c.a, c.b, got, c.want)
		}
	}
}

// isSelfVia is what stops the proxy from popping a Via that is not its
// own — RFC 3261 §16.7 step 3.
func TestTopologyIsSelfVia(t *testing.T) {
	topo := testTopology(t)
	self := []*sip.ViaHeader{
		{Transport: "UDP", Host: "203.0.113.7", Port: 16060},
		{Transport: "WS", Host: "203.0.113.7", Port: 18080},
		{Transport: "UDP", Host: "10.77.0.2", Port: 5060},
	}
	for _, v := range self {
		if !topo.isSelfVia(v) {
			t.Errorf("%s:%d not recognised as our own Via", v.Host, v.Port)
		}
	}
	notSelf := []*sip.ViaHeader{
		{Transport: "UDP", Host: "203.0.113.7", Port: 5060}, // right host, wrong port
		{Transport: "UDP", Host: "10.77.0.10", Port: 5060},  // the switch
		{Transport: "UDP", Host: "198.51.100.9", Port: 5060},
		{Transport: "UDP", Host: "phone.example", Port: 5060}, // not an IP
		nil,
	}
	for _, v := range notSelf {
		if topo.isSelfVia(v) {
			t.Errorf("%v wrongly recognised as our own Via", v)
		}
	}
	// A Via with no port falls back to the transport's default, which must
	// not accidentally match one of our listeners.
	if topo.isSelfVia(&sip.ViaHeader{Transport: "UDP", Host: "203.0.113.7"}) {
		t.Error("a portless Via matched a listener on a non-default port")
	}
}
