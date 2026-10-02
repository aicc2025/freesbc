package media

import (
	"net/netip"
	"testing"
)

// Tests for production paths the rest of the suite never reached
// (audit P1-010).

// TestSetRTCPRemoteOverridesOnlyRTCP covers the a=rtcp override: it moves
// the RTCP destination of one side and leaves that side's RTP destination
// and the other side alone.
func TestSetRTCPRemoteOverridesOnlyRTCP(t *testing.T) {
	s := &Session{}
	for side := range s.rtp {
		s.rtp[side] = &latch{mode: LatchLoose}
		s.rtcp[side] = &latch{mode: LatchLoose}
	}
	s.SetRemote(SideA, netip.MustParseAddrPort("192.0.2.10:4000"))
	s.SetRemote(SideB, netip.MustParseAddrPort("192.0.2.20:6000"))

	s.SetRTCPRemote(SideA, netip.MustParseAddrPort("192.0.2.10:4999"))

	if got := s.rtcp[SideA].target(); got == nil || got.Port != 4999 || got.IP.String() != "192.0.2.10" {
		t.Errorf("side A RTCP target = %v, want 192.0.2.10:4999", got)
	}
	if got := s.rtp[SideA].target(); got == nil || got.Port != 4000 {
		t.Errorf("side A RTP target = %v, want it unchanged at :4000", got)
	}
	if got := s.rtcp[SideB].target(); got == nil || got.Port != 6001 {
		t.Errorf("side B RTCP target = %v, want the RTP+1 default :6001", got)
	}
}
