package edge

import (
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

// Linux's weak host model delivers a datagram for any local address on any
// interface, so a datagram addressed to private.ip and sent into the public
// NIC reaches the private socket, where a spoofed switch source is believed
// (issue #90). SO_BINDTODEVICE would fix that too, but it pins the send path
// to the private interface as well: a switch node that is not reachable
// there would then look like a silent one and hide the transport error the
// passive failover relies on. The private socket therefore carries a classic
// BPF filter on the ingress interface instead: only datagrams that arrived
// on the interface owning private.ip (or were delivered locally, for a
// co-located switch) are queued, and the send path is untouched.
//
// The filter is Linux-only (SO_ATTACH_FILTER). Elsewhere it is a no-op and
// the host settings (strict rp_filter or a firewall rule) remain the
// mitigation; the caller logs a warning.

// Classic BPF encodings, from linux/bpf_common.h and linux/filter.h.
const (
	bpfLD          = 0x00
	bpfW           = 0x00
	bpfAbs         = 0x20
	bpfJmp         = 0x05
	bpfJeq         = 0x10
	bpfK           = 0x00
	bpfRet         = 0x06
	skfAdOff       = 0xFFFFF000 // SKF_AD_OFF
	skfAdIfindex   = 8          // SKF_AD_IFINDEX
	soAttachFilter = 0x1a       // Linux SO_ATTACH_FILTER
	bpfAccept      = 0xFFFFFFFF
)

// sockFilter is struct sock_filter and sockFprog is struct sock_fprog.
// They are spelled out instead of imported from x/sys/unix so this file
// still compiles on darwin, where the filter is never installed.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// privateSocketFilter returns a net.ListenConfig.Control that installs the
// ingress filter on the private socket, or nil where the platform has no
// SO_ATTACH_FILTER. ifname is the interface that owns private.ip.
func privateSocketFilter(ifname string) (func(network, address string, c syscall.RawConn) error, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	priv, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	return recvOnInterfaces(priv.Index, loop.Index), nil
}

// recvOnInterfaces accepts only datagrams whose ingress interface is one of
// ifindexes: the private interface for the wire, loopback for a co-located
// switch and the test harnesses. A wire datagram's ingress index is always
// the device it arrived on, so allowing loopback cannot admit one.
func recvOnInterfaces(ifindexes ...int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = attachIfindexFilter(int(fd), ifindexes)
		}); err != nil {
			return err
		}
		return serr
	}
}

// attachIfindexFilter installs the accept list on fd. The program loads
// skb->skb_iif and accepts when it equals one of ifindexes; every other
// datagram is dropped before it can be queued to the socket.
func attachIfindexFilter(fd int, ifindexes []int) error {
	// 0:              ld  skb->skb_iif
	// 1..n:           jeq ifindexes[i] -> accept, else the next test
	// n+1:            ret ACCEPT
	// n+2:            ret 0
	prog := make([]sockFilter, 0, len(ifindexes)+3)
	prog = append(prog, sockFilter{code: bpfLD | bpfW | bpfAbs, k: skfAdOff + skfAdIfindex})
	for i, idx := range ifindexes {
		// A match skips to the accept; a miss falls through to the next
		// test, and the last test's miss skips the accept to the drop.
		jf := uint8(0)
		if i == len(ifindexes)-1 {
			jf = 1
		}
		prog = append(prog, sockFilter{
			code: bpfJmp | bpfJeq | bpfK,
			jt:   uint8(len(ifindexes) - i - 1),
			jf:   jf,
			k:    uint32(idx),
		})
	}
	prog = append(prog, sockFilter{code: bpfRet | bpfK, k: bpfAccept})
	prog = append(prog, sockFilter{code: bpfRet | bpfK, k: 0})

	fprog := sockFprog{len: uint16(len(prog)), filter: &prog[0]}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_SOCKET), uintptr(soAttachFilter),
		uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
