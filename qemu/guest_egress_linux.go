//go:build linux

package qemu

import (
	"encoding/binary"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// guestTable is the nftables table the controller owns; it is replaced whole on every install.
const guestTable = "tinq_guest"

// install replaces the guest table in the current network namespace.
func (g *guestEgress) install() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: guestTable}
	c.AddTable(t)
	c.DelTable(t)
	t = c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: guestTable})
	accept := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{Name: "output", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	guest := c.AddChain(&nftables.Chain{Name: "guest", Table: t})
	acceptV := &expr.Verdict{Kind: expr.VerdictAccept}

	uid := make([]byte, 4)
	binary.NativeEndian.PutUint32(uid, g.UID)
	// Only a packet whose socket the guest uid owns enters the guest chain. The match is positive on
	// purpose: a packet with no socket (neighbour discovery, the kernel's own replies) cannot be
	// compared at all, and a "not the guest" rule would let it fall through to the guest's drop.
	c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uid},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: guest.Name}}})
	rule := func(e ...expr.Any) { c.AddRule(&nftables.Rule{Table: t, Chain: guest, Exprs: e}) }
	rule(&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: le32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, acceptV)
	for _, r := range g.Loopback {
		rule(append([]expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")}}, append(dport(unix.IPPROTO_TCP, r), acceptV)...)...)
	}
	for _, d := range g.DNS {
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			rule(append(append(daddr(netip.PrefixFrom(d, d.BitLen())), dport(proto, [2]uint16{53, 53})...), acceptV)...)
		}
	}
	for _, a := range g.Allow {
		if a.Proto == "" {
			rule(append(daddr(a.Prefix), acceptV)...)
			continue
		}
		proto := byte(unix.IPPROTO_TCP)
		if a.Proto == "udp" {
			proto = unix.IPPROTO_UDP
		}
		for _, r := range a.Ports {
			rule(append(append(daddr(a.Prefix), dport(proto, r)...), acceptV)...)
		}
	}
	rule(&expr.Verdict{Kind: expr.VerdictDrop})
	return c.Flush()
}

// daddr matches a destination inside p, for whichever family p is.
func daddr(p netip.Prefix) []expr.Any {
	family, off, n := byte(unix.NFPROTO_IPV6), uint32(24), 16
	if p.Addr().Is4() {
		family, off, n = unix.NFPROTO_IPV4, 16, 4
	}
	mask := make([]byte, n)
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: uint32(n)},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(n), Mask: mask, Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()},
	}
}

// dport matches a transport protocol and a destination port range.
func dport(proto byte, r [2]uint16) []expr.Any {
	be := func(p uint16) []byte { return []byte{byte(p >> 8), byte(p)} }
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: be(r[0]), ToData: be(r[1])},
	}
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// credential is the identity qemu runs as, with /dev/kvm's group so it can still accelerate.
func (g *guestEgress) credential() (*syscall.Credential, error) {
	cred := &syscall.Credential{Uid: g.UID, Gid: g.UID}
	var st unix.Stat_t
	if err := unix.Stat("/dev/kvm", &st); err == nil {
		cred.Groups = []uint32{st.Gid}
	}
	return cred, nil
}

// own gives the guest uid a machine's directory, which holds its disks, vars, pidfile and log.
func (g *guestEgress) own(dir string) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, int(g.UID), int(g.UID))
	})
}
