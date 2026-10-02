package edge

import "time"

// The upstream cooldown is hot: it is re-read from the store on every call
// or registration, so a reload changes it for the next one. The upstream node
// set is not: it is topology, built once from the startup snapshot. A reload
// that removes both upstream shapes therefore leaves the running topology in
// place while the live cooldown falls to zero (audit P2-CFG-002). Defaults
// make a configured cooldown non-zero, so a zero live value means "section
// absent" and the value the plane started with applies instead.

// upstreamPenalty is the cooldown for an upstream node that answered
// nothing: sip.upstreams.cooldown from the live snapshot, else the startup
// snapshot's.
func (s *Server) upstreamPenalty() time.Duration {
	if d := s.store.Current().SIP.Upstreams.Cooldown; d > 0 {
		return d.Std()
	}
	return s.boot.SIP.Upstreams.Cooldown.Std()
}
