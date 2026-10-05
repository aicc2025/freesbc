package edge

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// localInterface finds the interface that owns an address, which is what
// checkLocalAddr and the private socket's ingress filter both rest on.
func TestLocalInterface(t *testing.T) {
	name, ok, err := localInterface(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("localInterface(127.0.0.1): %v", err)
	}
	if !ok || name == "" {
		t.Fatalf("localInterface(127.0.0.1) = %q, %v; want a named interface", name, ok)
	}
	if _, ok, err := localInterface(netip.MustParseAddr("192.0.2.250")); err != nil || ok {
		t.Fatalf("localInterface(192.0.2.250) = _, %v, %v; want not found", ok, err)
	}
}

// The private socket's filter must accept datagrams received on an accepted
// interface and drop every other one. On Linux the accept list is a real
// BPF program; elsewhere the filter is a no-op and the test only checks the
// documented nil control.
func TestPrivateSocketFilter(t *testing.T) {
	if runtime.GOOS != "linux" {
		control, err := privateSocketFilter("lo")
		if err != nil || control != nil {
			t.Fatalf("privateSocketFilter off Linux: non-nil=%v, err=%v; want nil, nil", control != nil, err)
		}
		return
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	delivered := func(control func(network, address string, c syscall.RawConn) error) bool {
		lc := net.ListenConfig{Control: control}
		pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen with filter: %v", err)
		}
		defer pc.Close()
		peer, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8)
		_, _, err = pc.ReadFrom(buf)
		return err == nil
	}

	if !delivered(recvOnInterfaces(loop.Index)) {
		t.Error("a datagram received on the accepted interface was dropped")
	}
	if !delivered(recvOnInterfaces(999999, loop.Index)) {
		t.Error("the second accepted interface was not honoured")
	}
	if delivered(recvOnInterfaces(999999)) {
		t.Error("a datagram was delivered although its ingress interface was not accepted")
	}
}
