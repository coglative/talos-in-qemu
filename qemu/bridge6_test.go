package qemu

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// The bridge carries bytes from an IPv6 listener to QEMU's IPv4-only forward.
//
// QEMU user-mode networking has no IPv6 hostfwd, so a guest port can only be published on an IPv4
// address. On a single-stack IPv6 host -- every pod on this cluster -- the only IPv4 address in the
// namespace is 127.0.0.1, which nothing off-host can reach. Measured on a handler pod:
//
//	eth0  inet6 fd00:10:244:7::5d26/128
//	lo    inet  127.0.0.1/8
//
// So the guest is reachable from inside the netns and from nowhere else, which is why a venue can
// boot, report Running, and still be untestable.
func TestBridge6CarriesBytesToTheIPv4Forward(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()
	port := backend.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	b := newBridgeSet()
	defer b.closeAll()
	if err := b.ensure(port); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dial over IPv6: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want ping", buf)
	}
}

// ensure is idempotent: the controller calls it every tick for every running machine, and a second
// call must not fail with "address already in use" or replace a working listener.
func TestBridge6EnsureIsIdempotent(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	b := newBridgeSet()
	defer b.closeAll()
	if err := b.ensure(port); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if err := b.ensure(port); err != nil {
		t.Fatalf("second ensure must be a no-op, got: %v", err)
	}
	if n := b.count(); n != 1 {
		t.Fatalf("two ensures made %d listeners, want 1", n)
	}
}

// A bridge must not bind the IPv4 wildcard.
//
// Go's default "tcp" listener on [::] is dual-stack: it also claims 0.0.0.0:PORT, which QEMU
// already holds at 127.0.0.1:PORT. On Linux that bind then fails; on macOS it succeeds. So a test
// that merely binds a held port proves nothing here -- it passed with "tcp" substituted for "tcp6",
// which is the mutation it exists to catch. This asserts IPV6_V6ONLY on the socket instead, which
// is the property itself rather than one platform's consequence of it.
func TestBridge6ListenerIsV6Only(t *testing.T) {
	b := newBridgeSet()
	defer b.closeAll()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	if err := b.ensure(port); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	b.mu.Lock()
	ln := b.open[port]
	b.mu.Unlock()

	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v6only int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		v6only, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("getsockopt: %v", serr)
	}
	if v6only != 1 {
		t.Fatal("listener is dual-stack, so it also claims 0.0.0.0 and collides with QEMU's forward")
	}
}
