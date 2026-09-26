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
// loopback, DNS and an allow-list, and leaves the controller alone.
//
// Opt-in: with TINQ_GUEST_UID unset nothing changes. Set, the allow-list is TINQ_GUEST_EGRESS
// (space-separated prefixes; empty means replies, loopback and DNS only).

// guestEgress is the parsed configuration, or nil when the feature is off.
type guestEgress struct {
	UID   uint32
	Allow []netip.Prefix
	DNS   []netip.Addr
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
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("TINQ_GUEST_EGRESS: %w", err)
		}
		g.Allow = append(g.Allow, p.Masked())
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
