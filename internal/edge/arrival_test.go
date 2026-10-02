package edge

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

const arrOptions = "OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n" +
	"Via: SIP/2.0/UDP 127.0.0.1:5999;branch=z9hG4bK-m1\r\n" +
	"Max-Forwards: 70\r\nFrom: <sip:a@127.0.0.1>;tag=t1\r\nTo: <sip:x@127.0.0.1>\r\n" +
	"Call-ID: m1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"

func mustMarker(t *testing.T) *arrivalMarker {
	t.Helper()
	m, err := newArrivalMarker()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func parseReq(t *testing.T, b []byte) *sip.Request {
	t.Helper()
	msg, err := sip.ParseMessage(b)
	if err != nil {
		t.Fatalf("stamped datagram does not parse: %v\n%q", err, b)
	}
	req, ok := msg.(*sip.Request)
	if !ok {
		t.Fatalf("parsed as %T, want a request", msg)
	}
	return req
}

func TestArrivalMarkerSecretIsRandomPerProcess(t *testing.T) {
	a, b := mustMarker(t), mustMarker(t)
	if bytes.Equal(a.private, b.private) {
		t.Error("two markers share a secret")
	}
	// 128 bits of secret, hex encoded, plus the socket name.
	if got := strings.SplitN(string(a.private), ";", 2)[0]; len(got) != 32 {
		t.Errorf("secret %q is %d hex chars, want 32 (128 bits)", got, len(got))
	}
}

func TestArrivalStampInsertsHeaderAfterRequestLine(t *testing.T) {
	m := mustMarker(t)
	for _, tc := range []struct {
		name     string
		in       string
		wantLine string // the exact line that must follow the request line
	}{
		{"crlf", arrOptions, "\r\n"},
		{"lf only", strings.ReplaceAll(arrOptions, "\r\n", "\n"), "\n"},
		{"leading crlf", "\r\n\r\n" + arrOptions, "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.in)
			orig := append([]byte(nil), in...)
			for _, arr := range []arrival{arrPrivate} {
				out := m.stamp(arr, in)
				if !bytes.Equal(in, orig) {
					t.Fatal("stamp modified sipgo's read buffer in place")
				}
				want := arrivalHeader + ": " + string(m.value(arr)) + tc.wantLine
				reqLineEnd := bytes.Index(out, []byte("SIP/2.0"+tc.wantLine)) + len("SIP/2.0") + len(tc.wantLine)
				if !bytes.HasPrefix(out[reqLineEnd:], []byte(want)) {
					t.Fatalf("header not directly after the request line:\n%q", out)
				}
				// Nothing else changed.
				if got := bytes.Replace(out, []byte(want), nil, 1); !bytes.Equal(got, in) {
					t.Fatalf("stamp changed more than the one header line:\n%q", out)
				}
				if strings.Contains(tc.name, "lf only") {
					continue // the sipgo parser wants CRLF; the bytes are checked above
				}
				// The bytes are checked above; sip.ParseMessage itself wants
				// the request line first.
				req := parseReq(t, bytes.TrimLeft(out, "\r\n"))
				clean, got := m.take(req)
				if got != arr {
					t.Errorf("take = %d, want %d", got, arr)
				}
				if len(clean.GetHeaders(arrivalHeader)) != 0 {
					t.Error("marker still present after take")
				}
			}
		})
	}
}

func TestArrivalStampLeavesNonRequestsAlone(t *testing.T) {
	m := mustMarker(t)
	for name, in := range map[string]string{
		"response":       "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:5999;branch=z9hG4bK-m1\r\nContent-Length: 0\r\n\r\n",
		"response lf":    "SIP/2.0 200 OK\nContent-Length: 0\n\n",
		"keepalive crlf": "\r\n\r\n",
		"keepalive one":  "\r\n",
		"empty":          "",
		"no terminator":  "OPTIONS sip:x@127.0.0.1 SIP/2.0",
		"leading only":   "\r\n\r\nSIP/2.0 200 OK\r\n\r\n",
	} {
		in := []byte(in)
		out := m.stamp(arrPrivate, in)
		if !bytes.Equal(out, in) {
			t.Errorf("%s: stamped: %q", name, out)
		}
	}
	// A public arrival is never stamped.
	if out := m.stamp(arrPublic, []byte(arrOptions)); string(out) != arrOptions {
		t.Errorf("a public datagram was stamped: %q", out)
	}
}

func TestArrivalTakeForgedMarkerIsPublicAndStripped(t *testing.T) {
	m := mustMarker(t)
	for name, forged := range map[string]string{
		"wrong secret":      arrivalHeader + ": deadbeefdeadbeefdeadbeefdeadbeef;private\r\n",
		"lowercase name":    "x-freesbc-arrival: deadbeef;private\r\n",
		"empty value":       arrivalHeader + ":\r\n",
		"secret prefix":     arrivalHeader + ": " + string(m.private)[:10] + "\r\n",
		"secret wrong kind": arrivalHeader + ": " + strings.SplitN(string(m.private), ";", 2)[0] + ";other\r\n",
		"two headers":       arrivalHeader + ": a\r\n" + arrivalHeader + ": b\r\nX-Freesbc-ARRIVAL: c\r\n",
	} {
		raw := strings.Replace(arrOptions, "\r\nVia:", "\r\n"+forged+"Via:", 1)
		req := parseReq(t, []byte(raw))
		clean, got := m.take(req)
		if got != arrPublic {
			t.Errorf("%s: arrival = %d, want public", name, got)
		}
		if strings.Contains(strings.ToLower(clean.String()), "freesbc-arrival") {
			t.Errorf("%s: marker survived:\n%s", name, clean.String())
		}
	}
	// A request with no marker is public and returned as is.
	req := parseReq(t, []byte(arrOptions))
	if clean, got := m.take(req); got != arrPublic || clean != req {
		t.Error("an unmarked request must be public and untouched")
	}
}

func TestArrivalTakeDoesNotMutateSharedRequest(t *testing.T) {
	m := mustMarker(t)
	req := parseReq(t, m.stamp(arrPrivate, []byte(arrOptions)))
	clean, _ := m.take(req)
	if clean == req {
		t.Fatal("take must return a copy: the original is shared with sipgo's transaction goroutines")
	}
	if len(req.GetHeaders(arrivalHeader)) != 1 {
		t.Error("take edited the shared request in place")
	}
}

// The read filter stamps only reads on the trusted sockets, only from an
// upstream IP, and only requests.
func TestReadFilterStampsOnlyTrustedSockets(t *testing.T) {
	h := startHarness(t, false)
	f := h.srv.readFilter()
	udpAddr := func(hostport string) net.Addr {
		a, err := net.ResolveUDPAddr("udp", hostport)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	props := func(local, remote string) sip.TransportReadProps {
		return sip.TransportReadProps{Transport: "udp", LocalAddr: udpAddr(local), RemoteAddr: udpAddr(remote)}
	}
	run := func(p sip.TransportReadProps, data string) string {
		out, err := f(p, []byte(data))
		if err != nil {
			t.Fatalf("a read filter must never return an error: %v", err)
		}
		return string(out)
	}
	const upstream = "127.0.0.1:40000"

	for name, tc := range map[string]struct {
		local string
		arr   arrival
	}{
		"private": {h.privateSIP, arrPrivate},
	} {
		got := run(props(tc.local, upstream), arrOptions)
		if want := string(h.srv.marker.stamp(tc.arr, []byte(arrOptions))); got != want {
			t.Errorf("%s: read not stamped as %d:\n%q", name, tc.arr, got)
		}
		// Not an upstream IP: dropped, whatever the socket.
		if got := run(props(tc.local, "203.0.113.5:5060"), arrOptions); got != "" {
			t.Errorf("%s: a read from a non-upstream IP was accepted: %q", name, got)
		}
		// Responses are not stamped.
		res := "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
		if got := run(props(tc.local, upstream), res); got != res {
			t.Errorf("%s: a response was modified: %q", name, got)
		}
	}
	// A public listener is never stamped, from an upstream address or not,
	// and a forged marker passes through untouched for guard to strip.
	forged := strings.Replace(arrOptions, "\r\nVia:", "\r\n"+arrivalHeader+": "+string(h.srv.marker.private)+"\r\nVia:", 1)
	for _, remote := range []string{upstream, "203.0.113.5:5060"} {
		if got := run(props(h.publicUDP, remote), arrOptions); got != arrOptions {
			t.Errorf("public read from %s was modified: %q", remote, got)
		}
		if got := run(props(h.publicUDP, remote), forged); got != forged {
			t.Errorf("public read from %s with a marker was modified", remote)
		}
	}
	// The size cap still applies to a trusted read.
	big := arrOptions + strings.Repeat("x", maxMessageSize)
	if got := run(props(h.privateSIP, upstream), big); got != "" {
		t.Error("an oversized trusted read was accepted")
	}
}

// A client that forges the marker on a public listener is public: its
// REGISTER is forwarded like any phone's (not refused as FreeSWITCH's), and
// neither the forged header nor anything like it reaches the registrar.
func TestForgedArrivalMarkerOnPublicListenerIsPublicAndNeverForwarded(t *testing.T) {
	h := startHarness(t, false)
	conn := auditUDP(t)
	port := auditUDPPort(conn)
	fake := arrivalHeader + ": " + strings.Repeat("0", 32) + ";private\r\n"
	fake2 := strings.ToLower(arrivalHeader) + ": " + string(h.srv.marker.private[:8]) + "\r\n"
	auditRawRequest(t, conn, h.publicUDP, fmt.Sprintf("REGISTER sip:example.com SIP/2.0\r\n%s"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-forge;rport\r\n%s"+
		"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=forge\r\nTo: <sip:1001@example.com>\r\n"+
		"Call-ID: forge-1\r\nCSeq: 1 REGISTER\r\nContact: <sip:1001@127.0.0.1:%d>\r\nExpires: 600\r\n"+
		"Content-Length: 0\r\n\r\n", fake, port, fake2, port))
	var answer string
	auditRecvUntil(conn, 3*time.Second, func(b []byte) bool {
		if bytes.HasPrefix(b, []byte("SIP/2.0 ")) {
			answer = strings.SplitN(string(b), "\r\n", 2)[0]
			return true
		}
		return false
	})
	if !strings.HasPrefix(answer, "SIP/2.0 401") {
		t.Fatalf("forged-marker REGISTER answer = %q, want the registrar's 401 (it is a public REGISTER)", answer)
	}
	regs := h.fs.received(sip.REGISTER)
	if len(regs) == 0 {
		t.Fatal("the REGISTER never reached the registrar")
	}
	for _, r := range regs {
		if strings.Contains(strings.ToLower(r.String()), "freesbc-arrival") {
			t.Errorf("the forged marker was forwarded upstream:\n%s", r.String())
		}
	}
}

// The marker never appears in anything the proxy sends: not the requests it
// forwards to FreeSWITCH, not the responses it returns.
func TestArrivalMarkerNeverLeavesTheProxy(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()
	// A public phone call through to FreeSWITCH, then teardown.
	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
	// A private-bind INVITE (404) and raw exchanges on both sockets.
	warmPrivateSource(t, h)
	conn := auditUDP(t)
	for _, dst := range []string{h.privateSIP, h.publicUDP} {
		auditRawRequest(t, conn, dst, arrOptions)
		auditRecvUntil(conn, 500*time.Millisecond, func(b []byte) bool {
			if strings.Contains(strings.ToLower(string(b)), "freesbc-arrival") {
				t.Errorf("a response from %s carries the marker:\n%s", dst, b)
			}
			return false
		})
	}

	var all []*sip.Request
	for _, m := range []sip.RequestMethod{sip.INVITE, sip.ACK, sip.BYE} {
		all = append(all, h.fs.received(m)...)
	}
	for _, r := range all {
		if strings.Contains(strings.ToLower(r.String()), "freesbc-arrival") {
			t.Errorf("a request the proxy sent carries the marker:\n%s", r.String())
		}
	}
	if strings.Contains(strings.ToLower(res.String()), "freesbc-arrival") {
		t.Errorf("the response the phone received carries the marker:\n%s", res.String())
	}
}

// take removes every X-FreeSBC-* header, whatever its case, from a public
// request, and still reports it public; the original is left intact.
func TestTakeStripsEveryInternalHeaderCaseInsensitively(t *testing.T) {
	m, err := newArrivalMarker()
	if err != nil {
		t.Fatal(err)
	}
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "1", Host: "example.com"})
	req.AppendHeader(sip.NewHeader("X-FreeSBC-Carrier", "spoofed"))
	req.AppendHeader(sip.NewHeader("x-freesbc-extra", "1"))
	req.AppendHeader(sip.NewHeader("X-FREESBC-Arrival", "forged;private"))
	req.AppendHeader(sip.NewHeader("X-Other", "kept"))
	got, arr := m.take(req)
	if arr != arrPublic {
		t.Errorf("a forged marker made the request %v", arr)
	}
	if names := internalHeaderNames(got); len(names) != 0 {
		t.Errorf("internal headers left after take: %v", names)
	}
	if len(got.GetHeaders("X-Other")) != 1 {
		t.Error("take removed an unrelated header")
	}
	if len(internalHeaderNames(req)) != 3 {
		t.Error("take edited the shared original in place")
	}
}
