package edge

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file tests the switch's registration at a carrier (carrierreg.go):
// the proxied REGISTER with its rewritten Contact, the carrier-granted
// binding, the deterministic token, and the inbound call that comes back
// to the registering node with the switch's own Contact as Request-URI.

// carrierRegister builds a REGISTER the way a switch sends one for a
// carrier gateway: Request-URI the carrier, Contact the switch's own.
func carrierRegister(f *fakeSwitch, dest string, ruri, contact sip.Uri, expires int, callID string, cseq uint32, auth string) *sip.Request {
	req := sip.NewRequest(sip.REGISTER, ruri)
	acct := sip.Uri{User: "gw", Host: ruri.Host}
	from := &sip.FromHeader{Address: acct, Params: sip.NewParams()}
	from.Params.Add("tag", "regtag")
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: acct, Params: sip.NewParams()})
	id := sip.CallIDHeader(callID)
	req.AppendHeader(&id)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: cseq, MethodName: sip.REGISTER})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	c := &sip.ContactHeader{Address: contact, Params: sip.NewParams()}
	c.Params.Add("expires", fmt.Sprint(expires))
	req.AppendHeader(c)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	if auth != "" {
		req.AppendHeader(sip.NewHeader("Authorization", auth))
	}
	req.SetTransport("UDP")
	req.SetDestination(dest)
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}
	return req
}

// sendFromSwitch sends req from the fake switch and returns its final
// response.
func sendFromSwitch(t *testing.T, f *fakeSwitch, req *sip.Request) *sip.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("switch %s: %v", req.Method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res, ok := <-tx.Responses():
			if !ok {
				t.Fatalf("switch %s: no final response", req.Method)
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("switch %s: %v", req.Method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("switch %s timed out", req.Method)
		}
	}
}

// contactParam reads a parameter of a request's first Contact URI.
func contactToken(req *sip.Request) string {
	u, ok := fsip.ContactURI(req)
	if !ok {
		return ""
	}
	tok, _ := tokenOf(u)
	return tok
}

// The full exchange: a 401 challenge passes through untouched, the retried
// REGISTER's 200 stores the binding with the carrier's granted expiry and
// restores the switch's Contact, a refresh keeps the token, and Expires 0
// removes the binding.
func TestCarrierRegisterChallengeBindingRefreshUnregister(t *testing.T) {
	o := startOutboundRig(t)
	ruri := sip.Uri{Host: "127.0.0.1", Port: o.cport}
	orig := sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(o.fs.addr), UriParams: sip.NewParams()}
	orig.UriParams.Add("transport", "udp")
	node := o.upstream
	token := carrierToken(node, orig.String())
	const callID = "carrier-reg-1"

	// 1. No credentials: the carrier's challenge comes back untouched.
	res := sendFromSwitch(t, o.fs, carrierRegister(o.fs, o.privateSIP, ruri, orig, 3600, callID, 1, ""))
	if res.StatusCode != 401 {
		t.Fatalf("first REGISTER: got %d, want the carrier's 401", res.StatusCode)
	}
	if got := res.GetHeader("WWW-Authenticate"); got == nil ||
		got.Value() != `Digest realm="example.com", nonce="abc123nonce", algorithm=MD5, qop="auth"` {
		t.Errorf("challenge altered: %v", got)
	}
	if vias := res.GetHeaders("Via"); len(vias) != 1 || res.Via().Port != portOf(o.fs.addr) {
		t.Errorf("401 Vias = %v, want exactly the switch's own", vias)
	}
	regs := o.carrier.received(sip.REGISTER)
	if len(regs) != 1 {
		t.Fatalf("carrier saw %d REGISTERs, want 1", len(regs))
	}
	assertHidden(t, o, "REGISTER", regs[0], false)
	if regs[0].Recipient.String() != ruri.String() {
		t.Errorf("Request-URI = %s, want it unchanged (%s)", regs[0].Recipient.String(), ruri.String())
	}
	c, _ := fsip.ContactURI(regs[0])
	if c.User != "gw" || c.Port != o.publicPort() || contactToken(regs[0]) != token {
		t.Errorf("Contact toward the carrier = %s, want sip:gw@<public>:%d;fsbc=%s", c.String(), o.publicPort(), token)
	}
	if v, _ := regs[0].Contact().Params.Get("expires"); v != "3600" {
		t.Errorf("Contact expires parameter = %q, want the switch's 3600 kept", v)
	}
	if _, found := o.srv.carrierRegs.lookup(token); found {
		t.Error("a binding exists after a challenge")
	}

	// 2. The retry with credentials: 200, binding stored for what the
	// carrier GRANTED (120), Contact restored with that expiry.
	const auth = `Digest username="gw", realm="example.com", nonce="abc123nonce", uri="sip:127.0.0.1", response="0123456789abcdef"`
	res = sendFromSwitch(t, o.fs, carrierRegister(o.fs, o.privateSIP, ruri, orig, 3600, callID, 2, auth))
	if res.StatusCode != 200 {
		t.Fatalf("authenticated REGISTER: got %d, want 200", res.StatusCode)
	}
	regs = o.carrier.received(sip.REGISTER)
	if len(regs) != 2 {
		t.Fatalf("carrier saw %d REGISTERs, want 2", len(regs))
	}
	if h := regs[1].GetHeader("Authorization"); h == nil || h.Value() != auth {
		t.Errorf("Authorization altered: %v", h)
	}
	if regs[1].CallID().Value() != callID {
		t.Error("Call-ID changed")
	}
	rc, ok := fsip.ContactURI(res)
	if !ok || rc.String() != orig.String() {
		t.Errorf("Contact in the 200 = %v, want the switch's own %s", rc, orig.String())
	}
	if v, _ := res.Contact().Params.Get("expires"); v != "120" {
		t.Errorf("200 Contact expires = %q, want the carrier's 120", v)
	}
	b, found := o.srv.carrierRegs.lookup(token)
	if !found {
		t.Fatal("no binding after the 200")
	}
	if b.carrier != "alpha" || b.node != node || b.contact.String() != orig.String() {
		t.Errorf("binding = %+v", b)
	}
	if d := time.Until(b.expires); d < 110*time.Second || d > 125*time.Second {
		t.Errorf("binding expires in %v, want about the granted 120s", d)
	}
	if n := o.srv.metrics.Snapshot().CarrierRegistrations["alpha"]; n != 1 {
		t.Errorf("carrier registrations gauge = %d, want 1", n)
	}
	if n := o.srv.metrics.Snapshot().CarrierRequests["alpha/outbound/REGISTER"]; n != 2 {
		t.Errorf("outbound REGISTER metric = %d, want 2", n)
	}

	// 3. A refresh keeps the same token and a single binding.
	if res = sendFromSwitch(t, o.fs, carrierRegister(o.fs, o.privateSIP, ruri, orig, 3600, callID, 3, auth)); res.StatusCode != 200 {
		t.Fatalf("refresh: got %d", res.StatusCode)
	}
	regs = o.carrier.received(sip.REGISTER)
	if contactToken(regs[2]) != token {
		t.Errorf("refresh token = %q, want the same %q", contactToken(regs[2]), token)
	}
	if n := o.srv.carrierRegs.counts([]string{"alpha"})["alpha"]; n != 1 {
		t.Errorf("%d bindings after a refresh, want 1", n)
	}

	// 4. Expires 0: the carrier's 200 removes the binding.
	res = sendFromSwitch(t, o.fs, carrierRegister(o.fs, o.privateSIP, ruri, orig, 0, callID, 4, auth))
	if res.StatusCode != 200 {
		t.Fatalf("un-REGISTER: got %d", res.StatusCode)
	}
	if v, _ := res.Contact().Params.Get("expires"); v != "0" {
		t.Errorf("un-REGISTER 200 Contact expires = %q, want 0", v)
	}
	if _, found := o.srv.carrierRegs.lookup(token); found {
		t.Error("the binding survived Expires 0")
	}
	if n := o.srv.metrics.Snapshot().CarrierRegistrations["alpha"]; n != 0 {
		t.Errorf("carrier registrations gauge = %d after un-REGISTER, want 0", n)
	}
}

// The token is a function of the switch node and its Contact alone, so a
// restarted FreeSBC hands the carrier the same Contact: two Server
// instances on the same config produce the same token.
func TestCarrierRegistrationTokenSurvivesRestart(t *testing.T) {
	cport := freePort(t)
	carrier := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cport))
	t.Cleanup(carrier.stop)
	carrier.mu.Lock()
	carrier.challenge = false
	carrier.mu.Unlock()
	pubUDP, priv, up := freePort(t), freePort(t), freePort(t)
	node := fmt.Sprintf("127.0.0.1:%d", up)
	yaml := harnessYAML(t, []string{node}, pubUDP, 0, 0, nextMediaBase(t), "")
	yaml = strings.Replace(yaml, "edge:\n", fmt.Sprintf("edge:\n  carriers: {alpha: \"127.0.0.1:%d\"}\n", cport), 1)

	orig := sip.Uri{User: "gw", Host: "127.0.0.1", Port: up}
	var tokens []string
	for i := 0; i < 2; i++ {
		h := newHarness(t, yaml, priv)
		sw := startFakeSwitch(t, node)
		h.run()
		res := sendFromSwitch(t, sw, carrierRegister(sw, h.privateSIP,
			sip.Uri{Host: "127.0.0.1", Port: cport}, orig, 600, fmt.Sprintf("restart-%d", i), 1, ""))
		if res.StatusCode != 200 {
			t.Fatalf("run %d: REGISTER got %d", i, res.StatusCode)
		}
		regs := carrier.received(sip.REGISTER)
		tokens = append(tokens, contactToken(regs[len(regs)-1]))
		h.stop()
		sw.stop()
	}
	if tokens[0] == "" || tokens[0] != tokens[1] {
		t.Errorf("tokens across a restart = %v, want identical and non-empty", tokens)
	}
	if want := carrierToken(node, orig.String()); tokens[0] != want {
		t.Errorf("token = %q, want %q", tokens[0], want)
	}
}

func TestCarrierRegTableExpiryAndPrune(t *testing.T) {
	tab := newCarrierRegTable()
	live := carrierBinding{token: "live", carrier: "a", expires: time.Now().Add(time.Minute)}
	dead := carrierBinding{token: "dead", carrier: "a", expires: time.Now().Add(-time.Second)}
	tab.put(live)
	tab.put(dead)
	if _, ok := tab.lookup("dead"); ok {
		t.Error("an expired binding was found before pruning")
	}
	if got := tab.counts([]string{"a", "b"}); got["a"] != 1 || got["b"] != 0 {
		t.Errorf("counts = %v, want a=1 b=0", got)
	}
	if n := tab.prune(); n != 1 {
		t.Errorf("prune removed %d, want 1", n)
	}
	if _, ok := tab.lookup("live"); !ok {
		t.Error("the live binding was pruned")
	}
}

// twoNodeRig is two switch nodes (their carrier port is their own port) and
// a carrier that is both the registrar (UAS) and the caller (UAC).
type twoNodeRig struct {
	*harness
	carrier *client
	n1, n2  string
	sw      map[string]*fakeSwitch
}

func startTwoNodeRig(t *testing.T) *twoNodeRig {
	t.Helper()
	carrier := newUDPClient(t)
	up1, up2 := freePort(t), freePort(t)
	n1, n2 := fmt.Sprintf("127.0.0.1:%d", up1), fmt.Sprintf("127.0.0.1:%d", up2)
	yaml := harnessYAML(t, []string{n1, n2}, freePort(t), 0, 0, nextMediaBase(t), "")
	yaml = strings.Replace(yaml, "edge:\n", fmt.Sprintf("edge:\n  carriers: {alpha: \"%s\"}\n", carrier.local), 1)
	h := newHarness(t, yaml, freePort(t))
	rig := &twoNodeRig{harness: h, carrier: carrier, n1: n1, n2: n2, sw: map[string]*fakeSwitch{}}
	for _, n := range []string{n1, n2} {
		rig.sw[n] = startFakeSwitch(t, n)
		h.upstreams[n] = rig.sw[n]
	}
	carrier.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if req.Method == sip.REGISTER {
			if c, ok := fsip.ContactURI(req); ok {
				echo := &sip.ContactHeader{Address: c, Params: sip.NewParams()}
				echo.Params.Add("expires", "120")
				res.AppendHeader(echo)
			}
		}
		_ = tx.Respond(res)
	})
	h.run()
	return rig
}

// register registers a gateway Contact from node's switch and returns the
// Contact URI the carrier was given and the switch's original one.
func (r *twoNodeRig) register(t *testing.T, node string) (given, orig sip.Uri) {
	t.Helper()
	sw := r.sw[node]
	orig = sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(node), UriParams: sip.NewParams()}
	orig.UriParams.Add("transport", "udp")
	drain(r.carrier.inbound)
	ruri := sip.Uri{Host: "127.0.0.1", Port: portOf(r.carrier.local)}
	if res := sendFromSwitch(t, sw, carrierRegister(sw, r.privateSIP, ruri, orig, 600, "reg-"+node, 1, "")); res.StatusCode != 200 {
		t.Fatalf("REGISTER from %s: got %d", node, res.StatusCode)
	}
	select {
	case req := <-r.carrier.inbound:
		given, _ = fsip.ContactURI(req)
	case <-time.After(3 * time.Second):
		t.Fatal("the carrier never saw the REGISTER")
	}
	return given, orig
}

// carrierCall places an INVITE from the carrier to ruri, from the carrier's
// own address, and completes and ends the call.
func (r *twoNodeRig) carrierCall(t *testing.T, ruri sip.Uri) {
	t.Helper()
	inv := r.carrier.buildInvite("+15551230000", ruri.User, "example.com", phoneOfferSDP(30001))
	inv.Recipient = ruri
	inv.Laddr = sip.Addr{IP: net.IPv4(127, 0, 0, 1), Port: portOf(r.carrier.local)}
	res := r.carrier.do(t, inv, r.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE: got %d, want 200", res.StatusCode)
	}
	sendAck(t, r.carrier, inv, res, r.publicUDP)
	bye := buildBye(r.carrier, inv, res)
	bye.Laddr = inv.Laddr
	if b := r.carrier.do(t, bye, r.publicUDP); b.StatusCode != 200 {
		t.Fatalf("BYE: %d", b.StatusCode)
	}
}

// hashedNode is the node the hash pool picks for user.
func (r *twoNodeRig) hashedNode(user string) string {
	name, _, _ := r.srv.selectUpstream(user)
	return name
}

func (r *twoNodeRig) otherNode(n string) string {
	if n == r.n1 {
		return r.n2
	}
	return r.n1
}

// An inbound call whose Request-URI carries the registration token goes to
// the node that registered (and only that node), with the node's original
// Contact as the Request-URI; unknown and expired tokens, and a client
// token, fall back to the hash pool with the Request-URI unchanged. The
// carrier and client token tables never resolve each other's tokens.
func TestCarrierInboundTokenRestore(t *testing.T) {
	r := startTwoNodeRig(t)
	hashed := r.hashedNode("gw")
	registrar := r.otherNode(hashed) // the token must beat the hash

	given, orig := r.register(t, registrar)
	tok, ok := tokenOf(given)
	if !ok || given.Port != portOf(r.publicUDP) {
		t.Fatalf("Contact the carrier was given = %s, want a public address with a token", given.String())
	}

	// Token → the registering node, Request-URI = its original Contact.
	r.carrierCall(t, given)
	got := r.sw[registrar].waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the registering node saw %d INVITEs, want 1", len(got))
	}
	if got[0].Recipient.String() != orig.String() {
		t.Errorf("Request-URI = %s, want the switch's original Contact %s", got[0].Recipient.String(), orig.String())
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
	if n := len(r.sw[hashed].received(sip.INVITE)); n != 0 {
		t.Errorf("the hash-pool node saw %d INVITEs for a registered Contact, want 0", n)
	}
	waitForRelease(t, r.harness)

	// An unknown token → the hash pool, Request-URI unchanged.
	bogus := given
	bogus.UriParams = sip.NewParams()
	bogus.UriParams.Add(contactTokenParam, "unknowntoken")
	r.carrierCall(t, bogus)
	if g := r.sw[hashed].waitFor(sip.INVITE, 1, 3*time.Second); len(g) != 1 || g[0].Recipient.String() != bogus.String() {
		t.Errorf("unknown token: hash node INVITEs = %v, want one with the Request-URI unchanged", g)
	}
	waitForRelease(t, r.harness)

	// An expired registration is the same as an unknown one.
	r.srv.carrierRegs.put(carrierBinding{token: tok, carrier: "alpha", node: registrar, contact: orig, expires: time.Now().Add(-time.Second)})
	r.carrierCall(t, given)
	if g := r.sw[hashed].waitFor(sip.INVITE, 2, 3*time.Second); len(g) != 2 || g[1].Recipient.String() != given.String() {
		t.Errorf("expired token: hash node INVITEs = %d, want a second one with the Request-URI unchanged", len(g))
	}
	waitForRelease(t, r.harness)

	// A client's token is not a carrier registration: the carrier path
	// never resolves it, and a carrier token is no client's.
	_, err := r.srv.loc.Put(Binding{Token: "clienttoken1", AOR: "1001@example.com", User: "1001", Transport: "udp",
		CallID: "c1", Source: netip.MustParseAddrPort("127.0.0.1:40000"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := r.srv.carrierRegs.lookup("clienttoken1"); found {
		t.Error("the carrier table resolved a client token")
	}
	if _, found := r.srv.loc.ByToken(tok); found {
		t.Error("the client table resolved a carrier token")
	}
	clientURI := sip.Uri{User: "gw", Host: given.Host, Port: given.Port, UriParams: sip.NewParams()}
	clientURI.UriParams.Add(contactTokenParam, "clienttoken1")
	before := len(r.sw[hashed].received(sip.INVITE))
	r.carrierCall(t, clientURI)
	if g := r.sw[hashed].waitFor(sip.INVITE, before+1, 3*time.Second); len(g) != before+1 || g[before].Recipient.String() != clientURI.String() {
		t.Errorf("a client token on a carrier INVITE was not left to the hash pool unchanged")
	}
	// And the switch addressing a carrier token as a client finds nobody.
	res := switchRequest(t, r.sw[registrar], sip.INVITE, given, r.privateSIP)
	if res.StatusCode != 404 {
		t.Errorf("switch INVITE naming a carrier token as a client: got %d, want 404", res.StatusCode)
	}
}
