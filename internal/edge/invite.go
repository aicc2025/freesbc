package edge

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// inviteTimeout bounds an INVITE transaction end to end. It is longer than
// a typical ring cap because the far end, not FreeSBC, decides when to
// give up; this is a backstop against a transaction that never finalises
// pinning a media session forever.
const inviteTimeout = 5 * time.Minute

// maxEarlyPerSource caps the calls one public source IP may have in
// flight — media allocated, no answer yet — at once. Media is anchored
// before the INVITE reaches FreeSWITCH, and so before FreeSWITCH has
// authenticated the caller: without a cap, an unauthenticated flood holds
// a port pair per INVITE on each plane (plus, for a browser offer, an ICE
// agent) for the length of FreeSWITCH's 407 round trip, or up to Timer B
// when the upstream is silent. The cap is per IP, not per transport
// address, so it also bounds a flood spread over many source ports; it is
// generous enough for many phones ringing out through one NAT at once.
const maxEarlyPerSource = 64

// onInvite proxies a call in whichever direction it is going and anchors
// its media.
//
// The two directions are genuinely different — one starts from a public
// client and ends at FreeSWITCH, the other starts at FreeSWITCH and ends
// at a registered binding — but they share this shape:
//
//	parse the offer → allocate media → build the far-side offer →
//	forward → on each fork's answer, negotiate codecs and build the
//	near-side answer → on the 2xx, confirm the dialog → relay.
func (s *Server) onInvite(req *sip.Request, tx sip.ServerTransaction, in inbound) {
	src := in.src
	inDialog := isInDialog(req)
	if !inDialog && !in.private() && !s.admitPublicInvite(req, src) {
		// Admission (issue #86; admission.go): a public out-of-dialog
		// INVITE from a source that is neither a carrier source nor a
		// registered transport address is dropped before
		// anything answers it — ahead of the 100rel check below, whose 420
		// would otherwise tell a scanner something. Returning without a
		// response is the whole mechanism: sipgo's Server.handleRequest
		// calls TerminateGracefully when the handler returns, which, for a
		// transaction with no final response, is Terminate — it stops the
		// Timer_1xx that would otherwise send "100 Trying" at 200 ms,
		// removes the transaction and sends nothing. A retransmission of
		// the INVITE opens a fresh transaction and is dropped the same way.
		s.dropSilently(dropInviteNotAdmitted, req, src,
			"to", req.Recipient.User)
		return
	}
	if s.rejectRequired100rel(req, tx) {
		return // PRACK cannot pass the proxy (extensions.go)
	}
	if inDialog {
		s.onReInvite(req, tx, in.private())
		return
	}
	if in.private() {
		s.inviteToClient(req, tx)
		return
	}
	s.inviteToUpstream(req, tx, src)
}

// beginDialog opens the call's record, or answers 482 when the INVITE
// merges with one still in progress (RFC 3261 §8.2.2.2: same Call-ID and
// From tag as a transaction the proxy is already working on).
func (s *Server) beginDialog(req *sip.Request, tx sip.ServerTransaction, callerPlane plane) (*dialog, bool) {
	d, ok := s.dialogs.begin(req, callerPlane)
	if !ok {
		if s.dialogs.isClosed() { // closed never reopens, so this is exact
			s.reject(req, tx, 503, "Service Unavailable")
			return nil, false
		}
		s.reject(req, tx, 482, "Loop Detected")
		return nil, false
	}
	return d, true
}

// inviteToUpstream handles a call placed BY a public client.
func (s *Server) inviteToUpstream(req *sip.Request, tx sip.ServerTransaction, src netip.AddrPort) {
	from, ok := s.publicSideFor(req)
	if !ok {
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless INVITE would make FreeSBC the offerer toward
		// FreeSWITCH and then require a second negotiation against the
		// client's ACK. Not supported in this phase; refusing is honest.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	release, ok := s.admitEarly(src.Addr())
	if !ok {
		s.log.Warn("rejecting call: too many unanswered calls from one source",
			"public_remote", src.String(), "limit", maxEarlyPerSource, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	defer release()

	// ctx is the whole-series backstop: the 5-minute inviteTimeout,
	// cancellable — a client CANCEL cancels the series, never just the
	// attempt in flight.
	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	// One record from here to teardown: the dialog owns the media session,
	// the CANCEL bridge and the per-fork answers, and end() is the single
	// exit whether the call connects or not.
	d, ok := s.beginDialog(req, tx, planePublic)
	if !ok {
		return
	}
	defer d.endUnlessUp()

	offer, err := s.buildUpstreamOffer(ctx, d, body, src.Addr())
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	sess := offer.sess()

	// The CANCEL bridge is registered ONCE, for the whole series: the server
	// transaction the client's INVITE created is a single transaction across
	// every attempt, and its OnCancel hook must cancel whichever attempt is
	// in flight when the client gives up. The pending entry is re-tracked
	// per attempt below, and the cancel it holds is ALWAYS this series'
	// cancel — never a per-attempt one — so a CANCEL landing between two
	// attempts still ends the whole series through the stale entry, and the
	// loop's ctx check stops the next attempt from starting.
	//
	// The hook runs inside sipgo's transaction lock, and sipgo sends the
	// client its 487 only after the hook returns, so it does no network
	// I/O: it marks the call cancelled (from now on no 2xx can confirm it)
	// and hands the CANCEL to a goroutine.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			// No attempt in flight (between attempts, or before the first):
			// there is nothing to CANCEL on the wire, but the series must
			// still stop.
			cancel()
		}
	}) {
		// The CANCEL beat us here: the server transaction is already
		// terminated, the hook will never fire, and nothing has been sent
		// upstream yet. sipgo has already answered the client; ending the
		// series is the whole of the work left.
		return
	}
	defer d.untrack()

	cooldown := switchCooldown

	// The caller's hash order, cooled nodes at the tail: everything this
	// user does starts on the same switch, and a switch that just failed is
	// only dialed once its alternatives have been tried.
	for attempt, name := range s.upstreamOrder(hashUserFor(req)) {
		if ctx.Err() != nil {
			break // the caller is gone (or the backstop fired) mid-series
		}
		entry := s.topo.upstreamEntryFor(name)

		// Every attempt re-forwards the ORIGINAL request (prepareForward
		// clones, so the client's INVITE stays intact): a fresh Via branch
		// and Record-Route pair per attempt, same Call-ID/CSeq/From/To — it
		// is one dialog the client is still waiting on, whatever we had to
		// try to connect it.
		out, err := s.prepareForward(req, from, s.topo.private, entry.host, true)
		if err != nil {
			s.reject(req, tx, 483, "Too Many Hops")
			return
		}
		// The client's Contact must not reach FreeSWITCH: it names the
		// client's own address (or, for a browser, an unreachable .invalid
		// host), and FreeSWITCH would send in-dialog requests straight to it,
		// bypassing the SBC entirely.
		fsip.SetContact(out, s.topo.private.uri())
		fsip.SetSDPBody(out, offer.sdp)

		s.log.Info("proxying INVITE upstream",
			"sip_call_id", fsip.CallID(req), "direction", "public->private",
			"transport", from.transport, "public_remote", src.String(),
			"upstream", name, "attempt", attempt+1,
			"rtp_public_port", sess.publicPort,
			"rtp_private_port", sess.privatePort,
			"codec", codecNames(sess.negotiated()))

		// The pending entry points at THIS attempt's forwarded request — its
		// Via branch and destination are what a CANCEL must carry — BEFORE
		// the INVITE is sent, so no CANCEL can land between the two.
		a := &inviteAttempt{req: out, cancel: cancel}
		if !d.track(a) {
			break // the caller cancelled before this attempt started
		}
		// Started on ctx, the series context: the client transaction must
		// outlive the attempt so its CANCEL and its retransmissions are
		// still matched.
		clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
		if err != nil {
			s.log.Warn("forward INVITE upstream", "err", err, "sip_call_id", fsip.CallID(req),
				"upstream", name, "attempt", attempt+1)
			if ctx.Err() != nil {
				break // the caller is gone; nothing left to do
			}
			// The INVITE never got out: a zero-response failure while the
			// client is still waiting. Cooldown the node and let the next
			// one try.
			s.upstreamCooldown.Penalize(name, cooldown)
			continue
		}
		if d.markSent(a) {
			// A CANCEL took the attempt while the INVITE was being sent: it
			// could not go out ahead of the INVITE, so it goes out now.
			go s.sendCancel(a)
		}

		// In-dialog traffic rides the WINNING switch: directionFor sends the
		// client's ACKs and BYEs to this address, and the winner's Contact is
		// what their Request-URI names.
		l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, offer: offer,
			near: from, far: s.topo.private, callee: calleeUpstream,
			calleeRemote: entry.host, transport: from.transport}
		r := s.pumpInvite(ctx, l)

		if r.final != nil {
			// ANY final response ends the series — pumpInvite has already
			// relayed it (and, for a 2xx, confirmed the dialog first). A 486
			// is the callee's own judgement and must never be retried on
			// another switch (D7).
			s.upstreamCooldown.Recover(name)
			return
		}
		if r.finalised {
			return // the pump answered the client itself (488)
		}
		responded := r.responded
		// No final response. Retry another node ONLY when this one produced
		// nothing at all AND the attempt failed at the transport level. The
		// `!responded` half is an invariant, not a heuristic: a node that
		// answered had its answer negotiated and its media relay started by
		// pumpInvite, so a second attempt must never run — it would apply a
		// second answer and start the relay twice. A transaction that ended
		// without a transport error (the shared budget, a node that went
		// quiet after answering) is not something another node fixes either.
		if responded || clTx.Err() == nil {
			break
		}
		if ctx.Err() != nil {
			break // the caller is gone; nothing left to try
		}
		s.upstreamCooldown.Penalize(name, cooldown)
		s.log.Warn("upstream INVITE unanswered; entering cooldown",
			"upstream", name, "cooldown", cooldown.String(), "sip_call_id", fsip.CallID(req))
	}

	// Every node failed and nothing was relayed: 503 tells the client's own
	// failover (or the human) to try again rather than pretending the callee
	// is unreachable.
	s.giveUp(ctx, d, req, tx, 503, "Service Unavailable")
}

// giveUp sends the one final response a caller is owed when its INVITE
// ended without one being relayed: nothing when its own CANCEL already got
// it a 487 from sipgo; 408 when the backstop expired (RFC 3261 §16.7 step
// 6, §16.8); 487 when an orphan CANCEL ended it; the path's own status
// otherwise.
func (s *Server) giveUp(ctx context.Context, d *dialog, req *sip.Request, tx sip.ServerTransaction,
	code int, reason string) {
	switch {
	case d.callerCancelled():
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		s.reject(req, tx, 408, "Request Timeout")
	case ctx.Err() != nil || d.wasCancelled():
		s.reject(req, tx, 487, "Request Terminated")
	default:
		s.reject(req, tx, code, reason)
	}
}

// admitEarly counts a new unanswered call from a public source, refusing
// it when the source already has maxEarlyPerSource in flight. release
// uncounts it, and runs when the INVITE handler returns — by then the call
// is either up (and no longer early) or gone.
func (s *Server) admitEarly(src netip.Addr) (release func(), ok bool) {
	s.earlyMu.Lock()
	defer s.earlyMu.Unlock()
	if s.early[src] >= maxEarlyPerSource {
		return nil, false
	}
	s.early[src]++
	return func() {
		s.earlyMu.Lock()
		defer s.earlyMu.Unlock()
		if s.early[src]--; s.early[src] <= 0 {
			delete(s.early, src)
		}
	}, true
}

// hashUserFor derives the hashing identity of a request: the From user
// part, else the To user, else the Call-ID. From is the caller's own
// identity and is what stays constant across everything a user does, so a
// user's calls land on the switch its REGISTER landed on (aorOf hashes the
// same user for a REGISTER) with no shared state between the two paths.
func hashUserFor(req *sip.Request) string {
	if f := req.From(); f != nil && f.Address.User != "" {
		return f.Address.User
	}
	if t := req.To(); t != nil && t.Address.User != "" {
		return t.Address.User
	}
	return fsip.CallID(req)
}

// inviteToClient handles a call FreeSWITCH is placing to a registered
// client — acceptance criterion 3.
func (s *Server) inviteToClient(req *sip.Request, tx sip.ServerTransaction) {
	binding, ok := s.resolveTarget(req)
	if !ok {
		// Nothing registered under that contact any more. 404 is the
		// correct answer and lets FreeSWITCH fail over or play a
		// treatment, rather than ringing into nothing.
		s.reject(req, tx, 404, "Not Found")
		return
	}
	dest := binding.Source.String()
	to, ok := s.topo.publicSide(binding.Transport)
	if !ok {
		// A registered client FreeSBC cannot reach is 480: the endpoint is
		// gone, not the service.
		s.reject(req, tx, 480, "Temporarily Unavailable")
		return
	}
	body := req.Body()
	if len(body) == 0 {
		// An offerless INVITE would make FreeSBC the offerer toward the
		// far side and then require a second negotiation against the ACK.
		// Not supported in this phase; refusing is honest.
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}
	// A client registered over ws or wss is a browser: it accepts only a
	// DTLS-SRTP offer, and without webrtc.enabled there is no DTLS identity
	// to build one with. Offering plain RTP would only ring the browser
	// into a failure it reports as an opaque 480, so refuse here, loudly.
	toBrowser := isBrowserTransport(binding.Transport)
	if toBrowser && !s.webrtcEnabled {
		s.log.Warn("rejecting call to WebSocket client: webrtc.enabled is false, so no DTLS-SRTP offer can be built",
			"sip_call_id", fsip.CallID(req), "aor", binding.AOR, "transport", binding.Transport)
		s.reject(req, tx, 488, "Not Acceptable Here")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.inviteBudget())
	defer cancel()

	// One record from here to teardown, as in inviteToUpstream.
	d, ok := s.beginDialog(req, tx, planePrivate)
	if !ok {
		return
	}
	defer d.endUnlessUp()

	offer, err := s.buildPublicOffer(d, body, toBrowser)
	if err != nil {
		s.rejectMedia(req, tx, err)
		return
	}
	sess := offer.sess()

	out, err := s.prepareForward(req, s.topo.private, to, dest, true)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	// The Request-URI FreeSWITCH used names FreeSBC's own contact; the
	// client must see one addressed to itself.
	out.Recipient = clientRequestURI(binding)
	fsip.SetContact(out, to.uri())
	fsip.SetSDPBody(out, offer.sdp)

	s.log.Info("proxying INVITE to client",
		"sip_call_id", fsip.CallID(req), "direction", "private->public",
		"transport", binding.Transport, "aor", binding.AOR,
		"public_remote", dest,
		"rtp_public_port", sess.publicPort,
		"rtp_private_port", sess.privatePort,
		"webrtc", sess.IsWebRTC(),
		"codec", codecNames(sess.negotiated()))

	// A CANCEL from FreeSWITCH terminates this server transaction; when it
	// does, the INVITE we sent must be cancelled too or the far side would
	// keep ringing. A false return means the transaction is ALREADY
	// terminated — the CANCEL beat this registration — and nothing has
	// been sent yet: ending here is the whole of the work left.
	if !tx.OnCancel(func(*sip.Request) {
		if !s.cancelCall(d, cancelByCaller) {
			cancel()
		}
	}) {
		return
	}
	a := &inviteAttempt{req: out, cancel: cancel}
	if !d.track(a) {
		return // cancelled before the INVITE went out
	}
	defer d.untrack()

	clTx, err := s.client.TransactionRequest(ctx, out, noBuild)
	if err != nil {
		s.log.Warn("forward INVITE to client", "err", err, "aor", binding.AOR)
		s.giveUp(ctx, d, req, tx, 480, "Temporarily Unavailable")
		return
	}
	if d.markSent(a) {
		go s.sendCancel(a)
	}

	l := &inviteLeg{req: req, tx: tx, out: out, clTx: clTx, offer: offer,
		near: s.topo.private, far: to, callee: calleeClient,
		calleeRemote: dest, transport: binding.Transport, fromPrivate: true}
	if r := s.pumpInvite(ctx, l); !r.finalised {
		// The client never gave a final response: its INVITE timed out
		// (Timer B), its transport failed, or the backstop expired. The
		// proxy owes FreeSWITCH a final either way (RFC 3261 §16.7 step 6)
		// rather than leaving it to its own Timer B.
		code, reason := 480, "Temporarily Unavailable"
		if errors.Is(clTx.Err(), sip.ErrTransactionTimeout) {
			code, reason = 408, "Request Timeout"
		}
		s.giveUp(ctx, d, req, tx, code, reason)
	}
}

// publicSideFor returns the public side matching a request's transport.
func (s *Server) publicSideFor(req *sip.Request) (side, bool) {
	return s.topo.publicSide(sip.NetworkToLower(req.Transport()))
}

// resolveTarget finds the binding an inbound request is addressed to by the
// opaque token FreeSBC put in the registered Contact. There is no
// address-of-record fallback: an unknown or expired token is not found.
func (s *Server) resolveTarget(req *sip.Request) (Binding, bool) {
	return s.bindingForRequest(req)
}

// bindingForRequest extracts the binding token from a Request-URI (or from
// the topmost Route, where a strict-routing element may have moved it) and
// resolves it.
func (s *Server) bindingForRequest(req *sip.Request) (Binding, bool) {
	if tok, ok := tokenOf(req.Recipient); ok {
		if b, found := s.loc.ByToken(tok); found {
			return b, true
		}
	}
	if r := req.Route(); r != nil {
		if tok, ok := tokenOf(r.Address); ok {
			if b, found := s.loc.ByToken(tok); found {
				return b, true
			}
		}
	}
	return Binding{}, false
}

func tokenOf(u sip.Uri) (string, bool) {
	if u.UriParams == nil {
		return "", false
	}
	v, ok := u.UriParams.Get(contactTokenParam)
	if !ok || v == "" || len(v) > 64 {
		return "", false
	}
	return v, true
}

// clientRequestURI builds the Request-URI a client should see: its own
// address-of-record user at the address it registered from, with the
// transport it registered over.
func clientRequestURI(b Binding) sip.Uri {
	host := b.Source.Addr().String()
	port := int(b.Source.Port())
	params := sip.NewParams()
	if b.Transport != "udp" {
		params.Add("transport", b.Transport)
	}
	return sip.Uri{User: b.User, Host: host, Port: port, UriParams: params}
}

// rejectMedia maps a media-setup failure to the right SIP status: no
// common codec is 488 (the offer is unacceptable), an exhausted port pool
// is 503 (temporary capacity), anything else 500.
func (s *Server) rejectMedia(req *sip.Request, tx sip.ServerTransaction, err error) {
	switch {
	case errors.Is(err, errNoUsableCodec), errors.Is(err, errRenumbered):
		s.log.Info("rejecting call: media not negotiable", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	case errors.Is(err, errShuttingDown):
		s.reject(req, tx, 503, "Service Unavailable")
	case errors.Is(err, media.ErrPortsExhausted):
		s.metrics.PortAllocationFailed()
		s.log.Error("rejecting call: media ports exhausted", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 503, "Service Unavailable")
	default:
		s.log.Warn("rejecting call: media setup failed", "err", err, "sip_call_id", fsip.CallID(req))
		s.reject(req, tx, 488, "Not Acceptable Here")
	}
}

// isInDialog reports whether a request belongs to an established dialog,
// which RFC 3261 §12.2 identifies by the presence of a To tag.
func isInDialog(req *sip.Request) bool { return fsip.ToTag(req) != "" }

func codecNames(cs []sdp.Codec) string { return sdp.Describe(cs) }
