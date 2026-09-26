package qemu

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// GUEST EGRESS. qemu's user-mode network opens the guest's connections from qemu's own sockets, in
// the handler's network namespace, so anything the handler may reach the guest may reach too --
// including the apiserver the controller needs. Running qemu as its own uid lets the kernel tell the
// two apart: an nftables output rule keyed on the socket owner limits the guest to replies,
// DNS, named loopback ports and an allow-list, and leaves the controller alone.
//
// Opt-in: with TINQ_GUEST_UID unset nothing changes. Set, the allow-list is TINQ_GUEST_EGRESS
// (space-separated PREFIX or PREFIX@tcp|udp:PORTS; empty means replies and DNS only).

// guestEgress is the parsed configuration, or nil when the feature is off.
type guestEgress struct {
	UID   uint32
	Allow []allow
	DNS   []netip.Addr
	// Loopback are the TCP ports the guest may reach on the handler's own loopback. Everything else
	// there (other venues' forwards) is closed; unset means none.
	Loopback [][2]uint16
}

// allow is a destination prefix, optionally narrowed to one protocol and port ranges.
type allow struct {
	Prefix netip.Prefix
	Proto  string // "", "tcp" or "udp"
	Ports  [][2]uint16
}

// parseAllow reads "PREFIX" or "PREFIX@tcp|udp:P,P-P".
func parseAllow(s string) (allow, error) {
	pfx, rest, scoped := strings.Cut(s, "@")
	p, err := netip.ParsePrefix(pfx)
	if err != nil {
		return allow{}, err
	}
	a := allow{Prefix: p.Masked()}
	if !scoped {
		return a, nil
	}
	proto, list, ok := strings.Cut(rest, ":")
	if !ok || (proto != "tcp" && proto != "udp") {
		return allow{}, fmt.Errorf("%q: want PREFIX@tcp|udp:PORTS", s)
	}
	a.Proto = proto
	if a.Ports, err = parsePorts(list); err != nil {
		return allow{}, fmt.Errorf("%q: %w", s, err)
	}
	return a, nil
}

// parsePorts reads "P,P-P" into inclusive ranges.
func parsePorts(list string) ([][2]uint16, error) {
	var out [][2]uint16
	for _, r := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(r, "-")
		if !isRange {
			hi = lo
		}
		l, err1 := strconv.ParseUint(lo, 10, 16)
		h, err2 := strconv.ParseUint(hi, 10, 16)
		if err1 != nil || err2 != nil || l == 0 || l > h {
			return nil, fmt.Errorf("bad port range %q", r)
		}
		out = append(out, [2]uint16{uint16(l), uint16(h)})
	}
	return out, nil
}

func guestEgressFromEnv() (*guestEgress, error) {
	v := os.Getenv("TINQ_GUEST_UID")
	if v == "" {
		return nil, nil
	}
	uid, err := strconv.ParseUint(v, 10, 32)
	if err != nil || uid == 0 {
		return nil, fmt.Errorf("TINQ_GUEST_UID=%q: want a non-root uid", v)
	}
	g := &guestEgress{UID: uint32(uid)}
	for _, f := range strings.Fields(os.Getenv("TINQ_GUEST_EGRESS")) {
		a, err := parseAllow(f)
		if err != nil {
			return nil, fmt.Errorf("TINQ_GUEST_EGRESS: %w", err)
		}
		g.Allow = append(g.Allow, a)
	}
	if v := os.Getenv("TINQ_GUEST_LOOPBACK_PORTS"); v != "" {
		if g.Loopback, err = parsePorts(v); err != nil {
			return nil, fmt.Errorf("TINQ_GUEST_LOOPBACK_PORTS: %w", err)
		}
	}
	if g.DNS, err = nameservers("/etc/resolv.conf"); err != nil {
		return nil, err
	}
	return g, nil
}

// nameservers reads the resolvers qemu's slirp will forward the guest's DNS to.
func nameservers(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, a)
			}
		}
	}
	return out, sc.Err()
}
