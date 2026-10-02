package edge

import (
	"net/netip"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
)

// newMediaPools builds the edge proxy's two RTP port pools: public bound to
// public.bind and private bound to the effective private IP, both over the
// one rtp range. Each bind IP has its own port namespace, so the pools can
// never hand out the same socket even though they share a range.
//
// Addresses and range come from boot, the startup snapshot: SDP advertises
// the topology's media addresses, which are built once, so a reload that
// moved the range would make SDP and sockets disagree. rtp is therefore
// restart-only. timeout is read for every new session.
func newMediaPools(boot *config.Config, topo *topology, timeout func() time.Duration) (public, private *media.PlanePool) {
	r := boot.RTP
	plane := func(name string, bind, advertised netip.Addr) *media.PlanePool {
		return media.NewPlanePool(name, func() media.PlaneParams {
			return media.PlaneParams{
				MinPort: r.Min,
				MaxPort: r.Max,
				BindIP:  bind,
				Timeout: timeout(),
				// A plane that is itself on loopback (a single-host lab)
				// may send to loopback peers; any other plane never does.
				AllowLoopback: bind.IsLoopback() || advertised.IsLoopback(),
			}
		})
	}
	return plane("public", boot.PublicBind(), topo.publicMediaIP),
		plane("private", topo.privateMediaIP, topo.privateMediaIP)
}
