package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Issue #71: a far end that answers a re-INVITE with only a 183 and never
// a final must not leave the requester hanging or the forwarded re-INVITE
// open. At the backstop the requester gets 408 and the far end a CANCEL
// (RFC 3261 §16.8), so a later re-INVITE is not refused with 491 (§14.1).
func TestReInviteBackstopAnswers408AndCancels(t *testing.T) {
	h := startHarness(t, false)
	tags := make(chan string, 1)
	silent := h.fs.silentHook()
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 183, "Session Progress", nil))
		silent(req, tx)
	}))
	phone := newUDPClient(t)
	invite, res, phoneRTP := auditPhoneCall(t, h, phone)
	<-tags
	waitForDialog(t, h, fsip.CallID(invite))
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("initial ACK: FreeSWITCH saw %d", len(acks))
	}
	h.srv.inviteBackstop.Store(int64(700 * time.Millisecond))

	_, reRes := auditPhoneReInvite(t, h, phone, invite, res, 2, phoneOfferSDP(auditUDPPort(phoneRTP)))
	if reRes.StatusCode != 408 {
		t.Errorf("requester got %d to a re-INVITE that outlived its budget, want 408", reRes.StatusCode)
	}
	cancels := h.fs.waitFor(sip.CANCEL, 1, 3*time.Second)
	if len(cancels) != 1 {
		t.Fatalf("far end saw %d CANCEL(s), want 1", len(cancels))
	}
	if cs := cancels[0].CSeq(); cs == nil || cs.SeqNo != 2 {
		t.Errorf("CANCEL cancels CSeq %v, want the re-INVITE's 2", cs)
	}
}
