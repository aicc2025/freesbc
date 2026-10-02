package edge

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// This file tests the switch → carrier path: the stateful proxy with
// topology hiding. The fake carrier is a fakeSwitch (a sipgo UAS that
// records what it receives); the fake switch is h.fs, which sends to the
// private socket. Everything shares 127.0.0.1, so "no private address
// leaks" is asserted on ports: the private socket's, the switch's client
// port and the switch's carrier port never appear in anything the carrier
// receives.

type outboundRig struct {
	*carrierRig
	carrier *fakeSwitch
	cport   int
}

func startOutboundRig(t *testing.T) *outboundRig {
	t.Helper()
	cport := freePort(t)
	carrier := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cport))
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", cport), "", nil)
	rig.upstreams["carrier"] = carrier // stopped with the harness
	return &outboundRig{carrierRig: rig, carrier: carrier, cport: cport}
}

// ruri is a Request-URI addressed to the carrier.
func (o *outboundRig) ruri(user string) sip.Uri {
	return sip.Uri{User: user, Host: "127.0.0.1", Port: o.cport}
}

func (o *outboundRig) publicPort() int { return portOf(o.publicUDP) }

// answerWithTag makes the fake carrier ring and answer every INVITE with
// one To tag, as a UAS does, and returns the channel the tag arrives on.
func answerWithTag(f *fakeSwitch) chan string { return answerWithTagRR(f, nil) }

// answerWithTagRR is answerWithTag with an extra carrier Record-Route (a
// proxy in front of the carrier's gateway) above FreeSBC's echoed entry.
func answerWithTagRR(f *fakeSwitch, extra *sip.Uri) chan string {
	tags := make(chan string, 8)
	f.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		tag := sip.GenerateTagN(12)
		if t, ok := req.To().Params.Get("tag"); ok && t != "" {
			tag = t // a re-INVITE keeps the dialog's tag
		}
		ring := sip.NewResponseFromRequest(req, 180, "Ringing", nil)
		ring.To().Params.Add("tag", tag)
		_ = tx.Respond(ring)
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
		res.To().Params.Add("tag", tag)
		if extra != nil {
			res.PrependHeader(&sip.RecordRouteHeader{Address: *extra})
		}
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(f.addr)}})
		_ = tx.Respond(res)
		tags <- tag
		return true
	})
	return tags
}

// portLeak reports a "host:port" occurrence of any of the ports in raw.
func portLeak(raw string, addrs ...string) string {
	for _, a := range addrs {
		re := regexp.MustCompile(`:` + fmt.Sprint(portOf(a)) + `\b`)
		if re.MatchString(raw) {
			return a
		}
	}
	return ""
}

// assertHidden checks what a request toward the carrier may show: exactly
// one Via, FreeSBC's public one; Record-Route only the public entry (and
// only when wantRR); a public Contact; no Route and no X-FreeSBC-* header;
// and no private socket or switch address anywhere in it, body included.
func assertHidden(t *testing.T, o *outboundRig, what string, req *sip.Request, wantRR bool) {
	t.Helper()
	pub := o.publicPort()
	if vias := req.GetHeaders("Via"); len(vias) != 1 {
		t.Errorf("%s: %d Vias reached the carrier, want exactly 1", what, len(vias))
	} else if v := req.Via(); v.Port != pub {
		t.Errorf("%s: Via %s:%d, want FreeSBC's public port %d", what, v.Host, v.Port, pub)
	}
	rrs := req.GetHeaders("Record-Route")
	switch {
	case wantRR && len(rrs) != 1:
		t.Errorf("%s: %d Record-Routes, want only the public one", what, len(rrs))
	case !wantRR && len(rrs) != 0:
		t.Errorf("%s: %d Record-Routes on a non-dialog-forming request", what, len(rrs))
	}
	for _, h := range rrs {
		if rr := h.(*sip.RecordRouteHeader); rr.Address.Port != pub {
			t.Errorf("%s: Record-Route %s is not the public entry", what, rr.Address.String())
		}
	}
	if c := req.Contact(); c != nil && c.Address.Port != pub {
		t.Errorf("%s: Contact %s is not FreeSBC's public address", what, c.Address.String())
	}
	if n := len(req.GetHeaders("Route")); n != 0 {
		t.Errorf("%s: %d Route headers reached the carrier", what, n)
	}
	if names := internalHeaderNames(req); len(names) != 0 {
		t.Errorf("%s: internal headers %v reached the carrier", what, names)
	}
	if a := portLeak(req.String(), o.privateSIP, o.fs.addr, o.cs.addr); a != "" {
		t.Errorf("%s: %s leaked to the carrier:\n%s", what, a, req.String())
	}
}

// listenRTP opens a loopback UDP media socket on port.
func listenRTP(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A full outbound call: the carrier sees only FreeSBC's public identity,
// the switch gets its own Vias back and a route set that starts at the
// private socket, both SDPs are FreeSBC's, media flows both ways, ACK and
// BYE from the switch are hidden too.
func TestOutboundCallProxiedHiddenAndAnchored(t *testing.T) {
	o := startOutboundRig(t)
	answerWithTag(o.carrier)
	swRTP := listenRTP(t, o.fs.rtpPort)
	carRTP := listenRTP(t, o.carrier.rtpPort)

	ruri := o.ruri("+442071234567")
	res := o.fs.call(t, ruri, o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("outbound INVITE: got %d, want 200", res.StatusCode)
	}

	invs := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invs) != 1 {
		t.Fatalf("carrier saw %d INVITEs, want 1", len(invs))
	}
	inv := invs[0]
	assertHidden(t, o, "INVITE", inv, true)
	if inv.Recipient.String() != ruri.String() {
		t.Errorf("Request-URI = %s, want it unchanged (%s)", inv.Recipient.String(), ruri.String())
	}

	// Both SDPs are FreeSBC's: the carrier is offered a public anchor, the
	// switch is answered with a private one.
	offer, err := parseLabSDP(inv.Body())
	if err != nil {
		t.Fatalf("offer to the carrier: %v", err)
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatalf("answer to the switch: %v", err)
	}
	r := o.store.Current().RTP
	for what, port := range map[string]int{"offer": offer.Audio.Port, "answer": answer.Audio.Port} {
		if port < int(r.Min) || port > int(r.Max) {
			t.Errorf("%s advertises %d, want an SBC port in %d-%d", what, port, r.Min, r.Max)
		}
	}
	if offer.Audio.Port == o.fs.rtpPort || answer.Audio.Port == o.carrier.rtpPort {
		t.Error("a far end's own media port crossed the SBC")
	}

	// The switch gets its own Via back and a route set starting at the
	// private socket (the Record-Route list is reversed by a UAC).
	if vias := res.GetHeaders("Via"); len(vias) != 1 || res.Via().Port != portOf(o.fs.addr) {
		t.Errorf("response Vias = %v, want exactly the switch's own", vias)
	}
	rrs := res.GetHeaders("Record-Route")
	if len(rrs) != 2 {
		t.Fatalf("response Record-Routes = %d, want public and private", len(rrs))
	}
	if first := rrs[len(rrs)-1].(*sip.RecordRouteHeader); first.Address.Port != portOf(o.privateSIP) {
		t.Errorf("the switch's route set starts at %s, want the private socket %s", first.Address.String(), o.privateSIP)
	}
	if other := rrs[0].(*sip.RecordRouteHeader); other.Address.Port != o.publicPort() {
		t.Errorf("the public Record-Route = %s", other.Address.String())
	}

	// Media both ways.
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: offer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	if !relayReaches(t, swRTP, sbcPrivate, carRTP, rtpPacket(0, 100, 160)) {
		t.Error("switch → carrier audio never arrived")
	}
	if !relayReaches(t, carRTP, sbcPublic, swRTP, rtpPacket(0, 200, 160)) {
		t.Error("carrier → switch audio never arrived")
	}

	o.fs.sendAckTo2xx(t, res)
	acks := o.carrier.waitFor(sip.ACK, 1, 3*time.Second)
	if len(acks) != 1 {
		t.Fatalf("carrier saw %d ACKs, want 1", len(acks))
	}
	assertHidden(t, o, "ACK", acks[0], false)

	d := waitForDialog(t, o.harness, inv.CallID().Value())
	if d.carrierName() != "alpha" {
		t.Errorf("dialog carrier = %q, want alpha", d.carrierName())
	}
	if calls := o.srv.Calls(); len(calls) != 1 || calls[0].From != "switch:"+o.fs.addr || calls[0].To != "carrier:alpha" {
		t.Errorf("call record = %+v, want switch:%s → carrier:alpha", calls, o.fs.addr)
	}
	if n := o.srv.metrics.Snapshot().CarrierRequests["alpha/outbound/INVITE"]; n != 1 {
		t.Errorf("outbound INVITE metric = %d, want 1", n)
	}

	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE from the switch: %d\n%s", bye.StatusCode, bye.String()+fmt.Sprint(o.carrier.received(sip.BYE)))
	}
	byes := o.carrier.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 {
		t.Fatalf("carrier saw %d BYEs, want 1", len(byes))
	}
	assertHidden(t, o, "BYE", byes[0], false)
	if byes[0].Recipient.Port != portOf(o.carrier.addr) {
		t.Errorf("BYE Request-URI = %s, want the carrier's Contact", byes[0].Recipient.String())
	}
	waitForRelease(t, o.harness)
}

// A BYE from the carrier reaches the switch at its Contact, ends the
// dialog, and the carrier's own response carries no private address.
func TestOutboundByeFromCarrier(t *testing.T) {
	o := startOutboundRig(t)
	tags := answerWithTag(o.carrier)
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	o.fs.sendAckTo2xx(t, res)
	tag := <-tags
	invs := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invs) != 1 {
		t.Fatalf("carrier saw %d INVITEs", len(invs))
	}
	waitForDialog(t, o.harness, invs[0].CallID().Value())

	bye := o.carrier.inDialog(t, sip.BYE, invs[0], tag)
	if bye.StatusCode != 200 {
		t.Fatalf("BYE from the carrier: got %d, want 200", bye.StatusCode)
	}
	if a := portLeak(bye.String(), o.privateSIP, o.fs.addr, o.cs.addr); a != "" {
		t.Errorf("%s leaked in the response to the carrier's BYE:\n%s", a, bye.String())
	}
	got := o.fs.waitFor(sip.BYE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch saw %d BYEs, want 1", len(got))
	}
	waitForRelease(t, o.harness)
}

// switchReInvite sends a re-INVITE from the fake switch as the UAC of a
// call it placed, routed by the route set of res.
func switchReInvite(t *testing.T, f *fakeSwitch, res *sip.Response, body string) *sip.Response {
	t.Helper()
	req := sip.NewRequest(sip.INVITE, res.To().Address)
	sip.CopyHeaders("From", res, req)
	sip.CopyHeaders("To", res, req)
	sip.CopyHeaders("Call-ID", res, req)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: res.CSeq().SeqNo + 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	req.AppendHeader(&mf)
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "3003", Host: hostOf(f.addr), Port: portOf(f.addr)}})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	copyRouteFromRecordRoute(res, req)
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP",
		Host: hostOf(f.addr), Port: portOf(f.addr), Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	req.PrependHeader(via)
	req.SetBody([]byte(body))
	req.SetTransport("UDP")
	req.SetDestination(f.inDialogDest(t, req, res))
	req.Laddr = sip.Addr{IP: net.ParseIP(hostOf(f.addr)), Port: portOf(f.addr)}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("switch re-INVITE: %v", err)
	}
	defer tx.Terminate()
	for {
		select {
		case r, ok := <-tx.Responses():
			if !ok {
				t.Fatal("switch re-INVITE: no final response")
			}
			if r.StatusCode >= 200 {
				return r
			}
		case <-tx.Done():
			t.Fatalf("switch re-INVITE: %v", tx.Err())
		case <-ctx.Done():
			t.Fatal("switch re-INVITE timed out")
		}
	}
}

// A hold re-INVITE from the switch is hidden, its body rebuilt (the
// anchor does not move), and answered with the switch's own Vias.
func TestOutboundReInvite(t *testing.T) {
	o := startOutboundRig(t)
	answerWithTag(o.carrier)
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	o.fs.sendAckTo2xx(t, res)
	first, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	waitForDialog(t, o.harness, res.CallID().Value())

	hold := strings.Replace(phoneOfferSDP(o.fs.rtpPort), "a=sendrecv", "a=sendonly", 1)
	re := switchReInvite(t, o.fs, res, hold)
	if re.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d, want 200", re.StatusCode)
	}
	invs := o.carrier.waitFor(sip.INVITE, 2, 3*time.Second)
	if len(invs) != 2 {
		t.Fatalf("carrier saw %d INVITEs, want 2", len(invs))
	}
	assertHidden(t, o, "re-INVITE", invs[1], false)
	up, err := parseLabSDP(invs[1].Body())
	if err != nil {
		t.Fatal(err)
	}
	if up.Audio.Direction != sdp.SendOnly {
		t.Errorf("hold direction lost: %v", up.Audio.Direction)
	}
	if up.Audio.Port == o.fs.rtpPort {
		t.Error("the re-INVITE handed the carrier the switch's own media port")
	}
	if vias := re.GetHeaders("Via"); len(vias) != 1 || re.Via().Port != portOf(o.fs.addr) {
		t.Errorf("re-INVITE response Vias = %v, want exactly the switch's own", vias)
	}
	reAnswer, err := parseLabSDP(re.Body())
	if err != nil {
		t.Fatal(err)
	}
	if reAnswer.Audio.Port != first.Audio.Port {
		t.Errorf("the private anchor moved on re-INVITE: %d → %d", first.Audio.Port, reAnswer.Audio.Port)
	}
	if n := o.srv.metrics.Snapshot().CarrierRequests["alpha/outbound/INVITE"]; n != 2 {
		t.Errorf("outbound INVITE metric = %d, want 2 (the call and its re-INVITE)", n)
	}

	o.fs.sendAckTo2xx(t, re)
	if bye := o.fs.uacBye(t, re); bye.StatusCode != 200 {
		t.Fatalf("BYE: %d", bye.StatusCode)
	}
	waitForRelease(t, o.harness)
}

// A CANCEL from the switch cancels the INVITE sent to the carrier, hidden
// and with the same branch, and the switch gets its 487.
func TestOutboundCancel(t *testing.T) {
	o := startOutboundRig(t)
	o.carrier.setInviteHook(o.carrier.silentHook())
	req, final := o.fs.callAsync(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if got := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("carrier saw %d INVITEs, want 1", len(got))
	}
	cancel := buildCancelFor(req)
	cancel.SetTransport("UDP")
	cancel.SetDestination(o.privateSIP)
	cancel.Laddr = req.Laddr
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	tx, err := o.fs.cli.TransactionRequest(ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Terminate()
	select {
	case res := <-tx.Responses():
		if res.StatusCode != 200 {
			t.Fatalf("CANCEL: got %d, want 200", res.StatusCode)
		}
	case <-ctx.Done():
		t.Fatal("CANCEL got no response")
	}
	select {
	case res := <-final:
		if res == nil || res.StatusCode != 487 {
			t.Fatalf("INVITE final after CANCEL = %v, want 487", res)
		}
		if res.Via().Port != portOf(o.fs.addr) {
			t.Errorf("487 Via = %s, want the switch's own", res.Via().Value())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no final response after CANCEL")
	}
	cancels := o.carrier.waitFor(sip.CANCEL, 1, 3*time.Second)
	if len(cancels) != 1 {
		t.Fatalf("carrier saw %d CANCELs, want 1", len(cancels))
	}
	assertHidden(t, o, "CANCEL", cancels[0], false)
	inv := o.carrier.received(sip.INVITE)[0]
	if b1, _ := inv.Via().Params.Get("branch"); b1 == "" {
		t.Error("no branch on the INVITE")
	} else if b2, _ := cancels[0].Via().Params.Get("branch"); b1 != b2 {
		t.Errorf("CANCEL branch %q != INVITE branch %q", b2, b1)
	}
	waitForReleaseEventually(t, o.harness)
}

// An OPTIONS to a carrier is proxied (not answered locally), hidden, and
// the carrier's answer relayed with the switch's Vias.
func TestOutboundOptionsProxied(t *testing.T) {
	o := startOutboundRig(t)
	res := switchRequest(t, o.fs, sip.OPTIONS, sip.Uri{Host: "127.0.0.1", Port: o.cport}, o.privateSIP)
	if res.StatusCode != 200 {
		t.Fatalf("OPTIONS: got %d, want 200", res.StatusCode)
	}
	got := o.carrier.waitFor(sip.OPTIONS, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("carrier saw %d OPTIONS, want 1", len(got))
	}
	assertHidden(t, o, "OPTIONS", got[0], false)
	if vias := res.GetHeaders("Via"); len(vias) != 1 || res.Via().Port != portOf(o.fs.addr) {
		t.Errorf("OPTIONS response Vias = %v, want exactly the switch's own", vias)
	}
	if n := o.srv.metrics.Snapshot().CarrierRequests["alpha/outbound/OPTIONS"]; n != 1 {
		t.Errorf("outbound OPTIONS metric = %d, want 1", n)
	}
}

// Out-of-dialog BYE and INFO addressed to a carrier are 405: only
// REGISTER, INVITE and OPTIONS go to a carrier out of dialog.
func TestOutboundOtherMethodsAre405(t *testing.T) {
	o := startOutboundRig(t)
	for _, m := range []sip.RequestMethod{sip.BYE, sip.INFO} {
		res := switchRequest(t, o.fs, m, o.ruri("x"), o.privateSIP)
		if res.StatusCode != 405 {
			t.Errorf("%s to a carrier: got %d, want 405", m, res.StatusCode)
		}
	}
	if n := len(o.carrier.received(sip.BYE)) + len(o.carrier.received(sip.INFO)); n != 0 {
		t.Errorf("%d out-of-dialog requests reached the carrier", n)
	}
}

// The route set the carrier recorded survives on in-dialog requests: a
// carrier proxy in front of its gateway is still routed through, and
// nothing private is added.
func TestOutboundInDialogKeepsCarrierRoutes(t *testing.T) {
	o := startOutboundRig(t)
	lr := sip.NewParams()
	lr.Add("lr", "")
	answerWithTagRR(o.carrier, &sip.Uri{Host: "198.51.100.9", UriParams: lr})
	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	if n := len(res.GetHeaders("Record-Route")); n != 3 {
		t.Fatalf("response Record-Routes = %d, want carrier proxy, public, private", n)
	}
	o.fs.sendAckTo2xx(t, res)
	if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE: %d", bye.StatusCode)
	}
	byes := o.carrier.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 {
		t.Fatalf("carrier saw %d BYEs", len(byes))
	}
	routes := byes[0].GetHeaders("Route")
	if len(routes) != 1 || routes[0].(*sip.RouteHeader).Address.Host != "198.51.100.9" {
		t.Errorf("BYE Routes = %v, want only the carrier proxy's", routes)
	}
	if a := portLeak(byes[0].String(), o.privateSIP, o.fs.addr, o.cs.addr); a != "" {
		t.Errorf("%s leaked:\n%s", a, byes[0].String())
	}
	if len(byes[0].GetHeaders("Via")) != 1 {
		t.Error("switch Via reached the carrier")
	}
}

// The switch's own address in From and P-Asserted-Identity is masked to the
// public address toward the carrier and restored on the response; a carrier
// domain is left alone.
func TestOutboundIdentityMasked(t *testing.T) {
	o := startOutboundRig(t)
	answerWithTag(o.carrier)
	swPort := portOf(o.fs.addr)

	req := o.fs.callRequest(o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort),
		sip.NewHeader("P-Asserted-Identity", fmt.Sprintf("<sip:1000@127.0.0.1:%d>", swPort)),
		sip.NewHeader("Call-Info", fmt.Sprintf("<sip:127.0.0.1:%d>;answer-after=0", swPort)),
		sip.NewHeader("Alert-Info", fmt.Sprintf("<sip:127.0.0.1:%d>;info=alert-autoanswer", swPort)))
	origFrom := sip.Uri{User: "1000", Host: "127.0.0.1", Port: swPort}
	req.From().Address = origFrom
	tag, _ := req.From().Params.Get("tag")
	res := sendFromSwitch(t, o.fs, req)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	got := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("carrier saw %d INVITEs", len(got))
	}
	f := got[0].From()
	if f.Address.User != "1000" || f.Address.Host != "127.0.0.1" || f.Address.Port != 0 {
		t.Errorf("From toward the carrier = %s, want the public host without a port", f.Address.String())
	}
	if ft, _ := f.Params.Get("tag"); ft != tag {
		t.Errorf("From tag %q changed to %q", tag, ft)
	}
	if pai := got[0].GetHeader("P-Asserted-Identity"); pai == nil || strings.Contains(pai.Value(), fmt.Sprint(swPort)) {
		t.Errorf("P-Asserted-Identity = %v, want the switch's port gone", pai)
	}
	for name, params := range map[string]string{"Call-Info": ";answer-after=0", "Alert-Info": ";info=alert-autoanswer"} {
		if h := got[0].GetHeader(name); h == nil || h.Value() != "<sip:127.0.0.1>"+params {
			t.Errorf("%s = %v, want <sip:127.0.0.1>%s", name, h, params)
		}
	}
	if res.From().Address.String() != origFrom.String() {
		t.Errorf("200 From = %s, want the switch's original %s", res.From().Address.String(), origFrom.String())
	}

	// A carrier domain is not the switch: untouched.
	res2 := o.fs.call(t, o.ruri("+442071234568"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res2.StatusCode != 200 {
		t.Fatalf("second INVITE: %d", res2.StatusCode)
	}
	got = o.carrier.waitFor(sip.INVITE, 2, 3*time.Second)
	if len(got) != 2 || got[1].From().Address.Host != "example.com" {
		t.Errorf("a carrier-domain From was altered: %v", got[len(got)-1].From().Address.String())
	}
}
