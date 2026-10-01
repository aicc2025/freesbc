package edge

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Regression tests for GitHub issue #70: prepareForward mishandled
// Max-Forwards. RFC 3261 §16.3 step 3 rejects only a request that ARRIVES
// with 0, and §16.6 step 3 then decrements, so a request arriving with 1 is
// forwarded with 0.

// withMaxForwards sets (or, for a negative n, removes) the Max-Forwards
// header of a request built by the test helpers.
func withMaxForwards(req *sip.Request, n int) *sip.Request {
	req.RemoveHeader("Max-Forwards")
	if n >= 0 {
		mf := sip.MaxForwardsHeader(uint32(n))
		req.AppendHeader(&mf)
	}
	return req
}

// maxForwardsOf returns the header value of a request, or -1 if absent.
func maxForwardsOf(req *sip.Request) int {
	if mf := req.MaxForwards(); mf != nil {
		return int(mf.Val())
	}
	return -1
}

func TestPrepareForwardMaxForwards(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	from := h.srv.topo.public["udp"]
	to := h.srv.topo.private

	build := func(n int) *sip.Request {
		return withMaxForwards(phone.buildRegister("1001", "example.com", 600, ""), n)
	}

	t.Run("one is forwarded as zero", func(t *testing.T) {
		req := build(1)
		out, err := h.srv.prepareForward(req, from, to, h.upstream, false)
		if err != nil {
			t.Fatalf("Max-Forwards 1 refused: %v", err)
		}
		if got := maxForwardsOf(out); got != 0 {
			t.Errorf("forwarded Max-Forwards = %d, want 0", got)
		}
	})

	t.Run("zero is refused", func(t *testing.T) {
		out, err := h.srv.prepareForward(build(0), from, to, h.upstream, false)
		if !errors.Is(err, errMaxForwards) {
			t.Fatalf("err = %v, want errMaxForwards", err)
		}
		if out != nil {
			t.Errorf("a refused request still produced a forward: %v", out)
		}
	})

	t.Run("original is never mutated", func(t *testing.T) {
		// Failover loops call prepareForward once per attempt on the same
		// inbound request; every attempt must carry original-1.
		req := build(5)
		for i := 1; i <= 3; i++ {
			out, err := h.srv.prepareForward(req, from, to, h.upstream, false)
			if err != nil {
				t.Fatalf("attempt %d: %v", i, err)
			}
			if got := maxForwardsOf(out); got != 4 {
				t.Errorf("attempt %d forwarded Max-Forwards = %d, want 4", i, got)
			}
			if got := maxForwardsOf(req); got != 5 {
				t.Errorf("attempt %d mutated the inbound request: Max-Forwards = %d, want 5", i, got)
			}
		}
	})

	t.Run("absent gets the default", func(t *testing.T) {
		req := build(-1)
		out, err := h.srv.prepareForward(req, from, to, h.upstream, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := maxForwardsOf(out); got != 70 {
			t.Errorf("forwarded Max-Forwards = %d, want 70", got)
		}
		if got := maxForwardsOf(req); got != -1 {
			t.Errorf("inbound request gained a Max-Forwards header: %d", got)
		}
	})
}

// A REGISTER arriving with Max-Forwards 1 must reach FreeSWITCH with 0.
func TestMaxForwardsOneIsForwardedAsZero(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	req := withMaxForwards(phone.buildRegister("1001", "example.com", 600, ""), 1)
	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("REGISTER with Max-Forwards 1: got %d, want the upstream's 401", res.StatusCode)
	}
	regs := h.fs.waitFor(sip.REGISTER, 1, 3*time.Second)
	if len(regs) != 1 {
		t.Fatalf("FreeSWITCH saw %d REGISTERs, want 1", len(regs))
	}
	if got := maxForwardsOf(regs[0]); got != 0 {
		t.Errorf("upstream Max-Forwards = %d, want 0", got)
	}
}

// A REGISTER arriving with Max-Forwards 0 is answered 483 and goes nowhere.
func TestMaxForwardsZeroGets483(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	req := withMaxForwards(phone.buildRegister("1001", "example.com", 600, ""), 0)
	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 483 {
		t.Fatalf("REGISTER with Max-Forwards 0: got %d, want 483", res.StatusCode)
	}
	// Give a wrongly forwarded request time to arrive.
	time.Sleep(300 * time.Millisecond)
	if got := len(h.fs.received(sip.REGISTER)); got != 0 {
		t.Errorf("FreeSWITCH saw %d REGISTERs, want 0", got)
	}
}

// With the first upstream node dead, the retry against the second must
// carry original-1, not original-2.
func TestMaxForwardsSurvivesUpstreamFailover(t *testing.T) {
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessUpstreams(t, "", "30s", map[string]string{
		"fs-a": "192.0.2.1:5060", // unreachable: the send fails at once
		"fs-b": addrB,
	})
	fsB := switches["fs-b"]
	if h.srv.topo.upstreamNames[0] != "fs-a" {
		t.Fatalf("pool %v: fs-a must sort first for this test", h.srv.topo.upstreamNames)
	}
	user := userForNode(t, h.srv.topo, 0)

	phone := newUDPClient(t)
	req := withMaxForwards(phone.buildRegister(user, "example.com", 600, ""), 5)
	res := phone.do(t, req, h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("REGISTER via failover: got %d, want the 401 from fs-b", res.StatusCode)
	}
	regs := fsB.waitFor(sip.REGISTER, 1, 3*time.Second)
	if len(regs) != 1 {
		t.Fatalf("fs-b saw %d REGISTERs, want 1", len(regs))
	}
	if got := maxForwardsOf(regs[0]); got != 4 {
		t.Errorf("Max-Forwards after failover = %d, want 4 (5 minus one hop)", got)
	}
}
