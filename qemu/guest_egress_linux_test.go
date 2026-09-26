//go:build linux

package qemu

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The probe is this test binary re-run as another uid: it sends one datagram and exits 0 on a reply.
func TestMain(m *testing.M) {
	if a := os.Getenv("TINQ_EGRESS_PROBE_TCP"); a != "" {
		c, err := net.DialTimeout("tcp", a, 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		os.Exit(0)
	}
	if a := os.Getenv("TINQ_EGRESS_PROBE"); a != "" {
		c, err := net.DialTimeout("udp", a, time.Second)
		if err != nil {
			os.Exit(2)
		}
		for i := 0; i < 3; i++ {
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("x"))
			if n, err := c.Read(make([]byte, 8)); err == nil && n == 1 {
				os.Exit(0)
			}
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func inNS(t *testing.T, ns netns.NsHandle, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // discarded afterwards
		if err := netns.Set(ns); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func up(t *testing.T, name string, cidrs ...string) {
	t.Helper()
	ln, err := netlink.LinkByName(name)
	ok(t, err)
	for _, c := range cidrs {
		a, err := netlink.ParseAddr(c)
		ok(t, err)
		a.Flags = unix.IFA_F_NODAD
		ok(t, netlink.AddrAdd(ln, a))
	}
	ok(t, netlink.LinkSetUp(ln))
}

func echoOn(t *testing.T, addr string) {
	t.Helper()
	c, err := net.ListenPacket("udp", addr)
	ok(t, err)
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 8)
		for {
			n, from, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(b[:n], from)
		}
	}()
}

// probe runs the probe as uid (0 is root) from the calling thread's namespace. An address
// prefixed "tcp:" is a TCP connect; anything else is a UDP echo.
func probe(uid uint32, addr string) bool {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if a, ok := strings.CutPrefix(addr, "tcp:"); ok {
		cmd.Env = append(os.Environ(), "TINQ_EGRESS_PROBE_TCP="+a)
	} else {
		cmd.Env = append(os.Environ(), "TINQ_EGRESS_PROBE="+addr)
	}
	if uid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	}
	return cmd.Run() == nil
}

func TestGuestUIDReachesOnlyTheAllowListDNSAndLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT RUN (not a pass): needs root for network namespaces")
	}
	var handler, outside netns.NsHandle
	done := make(chan error)
	go func() {
		runtime.LockOSThread()
		var err error
		if outside, err = netns.New(); err == nil {
			handler, err = netns.New()
		}
		done <- err
	}()
	ok(t, <-done)
	t.Cleanup(func() { handler.Close(); outside.Close() })

	inNS(t, handler, func() {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = "h0"
		ok(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: "o0"}))
		o, err := netlink.LinkByName("o0")
		ok(t, err)
		ok(t, netlink.LinkSetNsFd(o, int(outside)))
		up(t, "h0", "fd00:98::1/64")
		up(t, "lo", "127.0.0.1/8")
		echoOn(t, "127.0.0.1:7")
		listenTCP(t, "127.0.0.1:443")
		listenTCP(t, "127.0.0.1:444")
	})
	inNS(t, outside, func() {
		up(t, "o0", "fd00:98::2/64", "fd00:98::5/128", "fd00:98::6/128", "fd00:98::53/128", "fd00:98::7/128")
		echoOn(t, "[fd00:98::5]:7")
		echoOn(t, "[fd00:98::6]:7")
		echoOn(t, "[fd00:98::6]:8")
		echoOn(t, "[fd00:98::53]:53")
		echoOn(t, "[fd00:98::7]:7")
	})

	inNS(t, handler, func() {
		// Unfiltered first: a destination that cannot be reached at all would make every "blocked" pass.
		if !probe(0, "[fd00:98::6]:7") {
			t.Fatal("control: root cannot reach the outside before any rule exists")
		}
		a, err := parseAllow("fd00:98::6/128@udp:7")
		ok(t, err)
		g := &guestEgress{UID: 64000, Allow: []allow{a},
			DNS: []netip.Addr{netip.MustParseAddr("fd00:98::53")}, Loopback: [][2]uint16{{443, 443}}}
		ok(t, g.install())
	})
	inNS(t, handler, func() {
		for _, c := range []struct {
			uid  uint32
			addr string
			want bool
			why  string
		}{
			{64000, "[fd00:98::6]:7", true, "an allowed destination"},
			{64000, "[fd00:98::5]:7", false, "a destination outside the allow-list"},
			{64000, "[fd00:98::53]:53", true, "DNS"},
			{64000, "[fd00:98::53]:7", false, "the DNS server on another port"},
			{64000, "[fd00:98::6]:8", false, "the allowed destination on another port"},
			{64000, "tcp:127.0.0.1:443", true, "the one loopback port named"},
			{64000, "tcp:127.0.0.1:444", false, "a loopback port not named (another venue's forward)"},
			{64000, "127.0.0.1:7", false, "loopback UDP"},
			{0, "[fd00:98::5]:7", true, "the controller, which is not confined"},
			{0, "[fd00:98::7]:7", true, "a neighbour nothing has resolved yet"},
		} {
			if got := probe(c.uid, c.addr); got != c.want {
				t.Errorf("uid %d to %s (%s): reached=%v, want %v", c.uid, c.addr, c.why, got, c.want)
			}
		}
	})
}

func listenTCP(t *testing.T, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	ok(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}
