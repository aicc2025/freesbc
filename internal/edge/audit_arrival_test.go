package edge

// Audit tests for the edge trust classification (issue #10): "is this
// FreeSWITCH" is decided by the local socket a datagram reached, never by
// the source address it carries.
//
// Loopback reproduces the defect without spoofing. Every endpoint in the
// harness shares 127.0.0.1, so a socket that has talked to the PRIVATE bind
// has, to the old source-keyed classification, exactly the identity of
// FreeSWITCH — and the same socket can then send to a PUBLIC listener,
// which is what a spoofed source (or FreeSWITCH's own socket) does on a
// real network: same source address:port, different local socket.

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// warmPrivateSource makes the fake FreeSWITCH's socket a known private-plane
// source: it sends an INVITE (answered 404, no such contact) to the private
// bind, which is exactly the traffic that filled the old source cache.
func warmPrivateSource(t *testing.T, h *harness) {
	t.Helper()
	nonMatch := sip.Uri{User: "9999", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	nonMatch.UriParams.Add(contactTokenParam, "no-such-token")
	if res := h.fs.call(t, nonMatch, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); res.StatusCode != 404 {
		t.Fatalf("warming INVITE: got %d, want 404", res.StatusCode)
	}
}

// audit: P2-EDG-003
// After a socket has sent to the private bind, the same socket (same source
// address and port) sending to a PUBLIC listener is still a public client:
// its REGISTER is forwarded to the registrar like any phone's — not refused
// 403 as "FreeSWITCH does not register through its own edge proxy" — and
// the shield applies to it: a scanner banned for a datagram it sent to a
// public listener is banned even though the same socket has been seen on
// the private bind.
func TestAuditPrivateSourceOnPublicListenerIsPublic(t *testing.T) {
	h := startHarness(t, false)
	conn := auditUDP(t)
	port := auditUDPPort(conn)

	// Warm: this socket talks to the private bind (its source IP is the
	// upstream's, which is all the trusted socket checks).
	auditRawRequest(t, conn, h.privateSIP, fmt.Sprintf("OPTIONS sip:proxy@127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-arr-warm;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:fs@127.0.0.1>;tag=warm\r\nTo: <sip:proxy@127.0.0.1>\r\n"+
		"Call-ID: arr-warm\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", port))
	if !auditRecvUntil(conn, 2*time.Second, func(b []byte) bool { return bytes.HasPrefix(b, []byte("SIP/2.0 200")) }) {
		t.Fatal("the private bind never answered the warming OPTIONS")
	}

	// The same socket registers on the PUBLIC listener.
	auditRawRequest(t, conn, h.publicUDP, fmt.Sprintf("REGISTER sip:example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-arr-reg;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=reg\r\nTo: <sip:1001@example.com>\r\n"+
		"Call-ID: arr-reg\r\nCSeq: 1 REGISTER\r\nContact: <sip:1001@127.0.0.1:%d>\r\nExpires: 600\r\n"+
		"Content-Length: 0\r\n\r\n", port, port))
	var status string
	auditRecvUntil(conn, 3*time.Second, func(b []byte) bool {
		if bytes.HasPrefix(b, []byte("SIP/2.0 ")) && bytes.Contains(b, []byte("Call-ID: arr-reg")) {
			status = strings.SplitN(string(b), "\r\n", 2)[0]
			return true
		}
		return false
	})
	if strings.HasPrefix(status, "SIP/2.0 403") {
		t.Errorf("P2-EDG-003 confirmed: a public REGISTER from a source seen on the private bind was refused as FreeSWITCH's own (%s)", status)
	} else if !strings.HasPrefix(status, "SIP/2.0 401") {
		t.Errorf("public REGISTER answer = %q, want the registrar's 401 challenge relayed", status)
	}
	if got := h.fs.received(sip.REGISTER); len(got) == 0 {
		t.Error("the REGISTER never reached the registrar")
	}

	// And the shield applies: a scanner datagram on the public listener
	// bans the socket.
	auditRawRequest(t, conn, h.publicUDP, fmt.Sprintf("OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-arr-scan;rport\r\n"+
		"Max-Forwards: 70\r\nFrom: <sip:s@127.0.0.1>;tag=scan\r\nTo: <sip:x@127.0.0.1>\r\n"+
		"Call-ID: arr-scan\r\nCSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n", port))
	self := netip.MustParseAddrPort(conn.LocalAddr().String())
	deadline := time.Now().Add(2 * time.Second)
	for !h.srv.shield.BannedFrom(self, "udp") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !h.srv.shield.BannedFrom(self, "udp") {
		t.Error("P2-EDG-003 confirmed: a scanner datagram from a source seen on the private bind was exempt from the shield on a public listener")
	}
}
