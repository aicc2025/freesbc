package edge

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file holds the carrier path's classification: who a request is for
// and who it is from. Carriers are the third kind of far end besides
// registered clients and the switch. The directory that resolves them is
// carrierdns.go; the inbound (carrier → switch) call path is
// inviteToUpstream with a carrier name; the outbound (switch → carrier)
// proxying is not built yet (see carrierNotImplemented).

// carrierHeader is the header FreeSBC stamps on every request it delivers
// to the switch's carrier port, naming the carrier it came from
// (edge.carriers name, or "unknown" for a carrier_sources address that
// matches no entry). The switch identifies inbound carrier calls by it.
const carrierHeader = "X-FreeSBC-Carrier"

// Directions of the carrier request metric: toward the switch, and toward
// a carrier.
const (
	dirInbound  = "inbound"  // carrier → switch
	dirOutbound = "outbound" // switch → carrier
)

// carrierKey is the canonical "host:port" an edge.carriers entry is
// matched by: host lower-cased without a trailing dot (a literal IP in
// canonical form), port defaulting to 5060.
func carrierKey(host string, port int) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	if port == 0 {
		port = config.DefaultCarrierPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// carrierURIsOf maps each edge.carriers entry's "host:port" to its name.
func carrierURIsOf(cfg *config.Config) map[string]string {
	m := map[string]string{}
	for _, c := range cfg.CarrierList() {
		m[carrierKey(c.Host, c.Port)] = c.Name
	}
	return m
}

// switchTarget is where a request from the switch is addressed.
type switchTarget int

const (
	// targetNotFound: addressed to nothing FreeSBC serves. The switch gets
	// 404; FreeSBC is never an open relay for it.
	targetNotFound switchTarget = iota
	// targetClient: the Request-URI (or topmost remaining Route) carries an
	// fsbc token.
	targetClient
	// targetCarrier: the Request-URI host[:port] is an edge.carriers entry.
	targetCarrier
	// targetSelf: addressed to FreeSBC's own signaling address.
	targetSelf
)

// classifySwitchRequest decides where an out-of-dialog request from the
// switch goes, by Request-URI only and never by registration state (issue
// #96, "Private socket"). A Route naming FreeSBC itself is skipped (loose
// routing). Then, in order:
//
//  1. the Request-URI, or the topmost remaining Route, carries an fsbc
//     token → targetClient (whether the token is live is the client path's
//     business: unknown or expired answers 404);
//  2. the Request-URI host[:port] equals an edge.carriers entry
//     (case-insensitive host, trailing dot ignored, port default 5060) →
//     targetCarrier, with the carrier's name;
//  3. the Request-URI names FreeSBC → targetSelf;
//  4. anything else → targetNotFound.
func (s *Server) classifySwitchRequest(req *sip.Request) (switchTarget, string) {
	if _, ok := tokenOf(req.Recipient); ok {
		return targetClient, ""
	}
	if r := s.firstForeignRoute(req); r != nil {
		if _, ok := tokenOf(r.Address); ok {
			return targetClient, ""
		}
	}
	if name, ok := s.carrierURIs[carrierKey(req.Recipient.Host, req.Recipient.Port)]; ok {
		return targetCarrier, name
	}
	if s.topo.isSelf(req.Recipient) {
		return targetSelf, ""
	}
	return targetNotFound, ""
}

// firstForeignRoute is the topmost Route header that does not name FreeSBC
// itself, or nil. FreeSBC's own Route (the switch's outbound proxy, or the
// private Record-Route coming back) is removed from the route set before
// anything else looks at it.
func (s *Server) firstForeignRoute(req *sip.Request) *sip.RouteHeader {
	for _, h := range req.GetHeaders("Route") {
		if r, ok := h.(*sip.RouteHeader); ok && !s.topo.isSelf(r.Address) {
			return r
		}
	}
	return nil
}

// carrierHashUser is the hashing identity of a carrier's request: the
// lower-cased Request-URI user (the DID), else the To user, else the
// Call-ID. Call-ID is the last resort so a request with neither still
// lands somewhere stable.
func carrierHashUser(req *sip.Request) string {
	if u := req.Recipient.User; u != "" {
		return strings.ToLower(u)
	}
	if t := req.To(); t != nil && t.Address.User != "" {
		return strings.ToLower(t.Address.User)
	}
	return fsip.CallID(req)
}

// carrierFallback reports whether a public request that matches no dialog
// record is a carrier's: its source is a carrier source and no live
// registration owns that transport address (a registration wins, as in
// admission).
func (s *Server) carrierFallback(req *sip.Request) (name string, ok bool) {
	src, ok := fsip.SourceAddrPort(req)
	if !ok || s.loc.HasSource(sip.NetworkToLower(req.Transport()), src) {
		return "", false
	}
	return s.carriers.snapshot().carrierFor(src)
}

// stampCarrier adds X-FreeSBC-Carrier to a request forwarded from the
// public side to the switch when it belongs to a carrier call: the
// dialog's carrier when the dialog is on record, else the carrier whose
// source it came from.
func (s *Server) stampCarrier(out, req *sip.Request, d *dialog) {
	name := ""
	if d != nil {
		name = d.carrierName()
	} else if n, ok := s.carrierFallback(req); ok {
		name = n
	}
	if name == "" {
		return
	}
	out.AppendHeader(sip.NewHeader(carrierHeader, name))
	s.metrics.CarrierRequest(name, dirInbound, req.Method.String())
}

// invitePrivate routes an out-of-dialog INVITE from the switch.
func (s *Server) invitePrivate(req *sip.Request, tx sip.ServerTransaction) {
	switch kind, name := s.classifySwitchRequest(req); kind {
	case targetClient:
		s.inviteToClient(req, tx)
	case targetCarrier:
		s.carrierNotImplemented(req, tx, name)
	default:
		s.reject(req, tx, 404, "Not Found")
	}
}

// carrierNotImplemented is the hook of the switch → carrier path. Proxying
// REGISTER, INVITE and OPTIONS to a carrier (topology hiding, the carrier
// registration token) is the next phase; until it lands the request is
// recognised, counted by nothing, and answered 501 so the switch fails
// over instead of waiting.
func (s *Server) carrierNotImplemented(req *sip.Request, tx sip.ServerTransaction, carrier string) {
	s.log.Warn("switch request to a carrier is not implemented yet",
		"carrier", carrier, "method", req.Method.String(), "sip_call_id", fsip.CallID(req))
	s.reject(req, tx, 501, "Not Implemented")
}
