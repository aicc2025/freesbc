package edge

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/emiago/sipgo/sip"
)

// arrival says which local socket a request came in on. It is the trust key
// of the whole edge plane: "is this FreeSWITCH" is decided by the socket the
// datagram reached, never by the address it claims to come from.
type arrival uint8

const (
	// arrPublic is every read on a public listener (UDP, WS, WSS), and any
	// request that carries no valid arrival marker. Nothing about the source
	// address can promote it: a spoofed or forged request is public.
	arrPublic arrival = iota
	// arrPrivate is a datagram that reached the private bind from an
	// upstream IP: FreeSWITCH talking to its own edge proxy.
	arrPrivate
)

// arrivalHeader is the internal header the read filter stamps on a request
// that reached a trusted socket, and guard reads and strips again before
// any handler runs. sipgo v1.4.3 hands a handler only the request's SOURCE,
// so the local socket — which only the transport read filter sees — has to
// travel with the message itself.
const arrivalHeader = "X-FreeSBC-Arrival"

// arrivalMarker mints and checks the arrival header. The header value is a
// per-process secret (128 random bits) plus the trusted socket's name, so a
// client that forges the header cannot be believed: it does not know the
// secret, and a wrong or absent value simply means arrPublic.
type arrivalMarker struct {
	private []byte // full header value for the private bind
}

func newArrivalMarker() (*arrivalMarker, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("arrival marker secret: %w", err)
	}
	secret := hex.EncodeToString(b[:])
	return &arrivalMarker{
		private: []byte(secret + ";private"),
	}, nil
}

// value is the header value stamped for a trusted arrival.
func (m *arrivalMarker) value(a arrival) []byte {
	switch a {
	case arrPrivate:
		return m.private
	}
	return nil
}

// stamp returns a copy of the datagram data with the arrival header
// inserted right after the request line, or data itself, untouched, when it
// is not a request that can carry one. It never writes to data: that is
// sipgo's read buffer.
//
// Only requests are stamped. A response's first line starts with "SIP/",
// and an empty or CRLF-only datagram (a keep-alive) has no first line at
// all. Leading CR/LF bytes before the request line are tolerated, as the
// parser tolerates them (RFC 3261 §7.5). The header uses the line
// terminator the request line itself uses, so an LF-only sender stays
// LF-only. A datagram with no line terminator is malformed; it is passed on
// unstamped, which fails closed: an unstamped request is public.
func (m *arrivalMarker) stamp(a arrival, data []byte) []byte {
	v := m.value(a)
	if v == nil {
		return data
	}
	start := 0
	for start < len(data) && (data[start] == '\r' || data[start] == '\n') {
		start++
	}
	rest := data[start:]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 || len(rest) == 0 {
		return data
	}
	line := rest[:nl]
	term := "\n"
	if len(line) > 0 && line[len(line)-1] == '\r' {
		term = "\r\n"
	}
	if bytes.HasPrefix(line, []byte("SIP/")) {
		return data // a response
	}
	insertAt := start + nl + 1
	out := make([]byte, 0, len(data)+len(arrivalHeader)+2+len(v)+len(term))
	out = append(out, data[:insertAt]...)
	out = append(out, arrivalHeader...)
	out = append(out, ": "...)
	out = append(out, v...)
	out = append(out, term...)
	out = append(out, data[insertAt:]...)
	return out
}

// take reads the arrival marker off req and returns the request the
// handler should use, together with the arrival. Every occurrence of the
// header — whatever its case and whoever wrote it — is gone from the
// returned request, so it can never be forwarded or echoed. sipgo's
// RemoveHeader is exact-name and removes one header per call, so the
// headers are found case-insensitively first and removed under the exact
// name each carries.
//
// A request that carries the header is CLONED and stripped on the copy, and
// the copy is returned: the original is shared with sipgo's own server
// transaction, whose "100 Trying" timer reads its headers from another
// goroutine (sipgo v1.4.3 transaction_server_tx.go), so editing it in place
// is a data race. A request with no marker — every ordinary public request
// — is returned as it is, at no cost.
//
// The arrival is trusted only when the first occurrence — the one the read
// filter inserts directly after the request line — equals a marker value
// exactly (constant-time). Anything else, a forged value included, is
// arrPublic.
func (m *arrivalMarker) take(req *sip.Request) (*sip.Request, arrival) {
	hs := req.GetHeaders(arrivalHeader)
	if len(hs) == 0 {
		return req, arrPublic
	}
	got := []byte(hs[0].Value())
	result := arrPublic
	if subtle.ConstantTimeCompare(got, m.private) == 1 {
		result = arrPrivate
	}
	clean := req.Clone()
	for _, h := range clean.GetHeaders(arrivalHeader) {
		clean.RemoveHeader(h.Name())
	}
	return clean, result
}
