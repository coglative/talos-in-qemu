package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/safe"
	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	blockres "github.com/siderolabs/talos/pkg/machinery/resources/block"
	netres "github.com/siderolabs/talos/pkg/machinery/resources/network"
)

// NODE FACTS, NOT PROBES. This file asks a maintenance-mode node QUESTIONS,
// renders the answers for a human, and refuses on them. Nothing here decides
// whether a node is READY, and nothing here may be used to — a fact about a
// node is not a verdict on it, and the refusals below are over facts already
// gathered, never over a node's state.
//
// That distinction is why this file exists at all rather than living in
// client.go, whose header rule (2) forbids any probe from comparing, returning
// or logging a version — because `talosctl version` prints a constant compiled
// into the binary and will do so with no node in sight. These functions run
// AFTER readiness has been established by a real round trip, and their answers
// become values written to the node's disk.

// NodeVersion asks a maintenance-mode node for its own Talos version.
//
// It NEVER errors on an unidentifiable version, only on a failed call: "" is a
// real answer and matches platform.InspectImageVersion's contract, so both
// sources of a version fail the same way and step 3's guard is the single place
// that refuses one. Returning an error here instead would put the refusal in
// two places and let them drift.
func NodeVersion(ctx context.Context, endpoint string) (string, error) {
	c, err := MaintenanceClient(ctx, endpoint)
	if err != nil {
		return "", err
	}

	defer c.Close() //nolint:errcheck

	resp, err := c.Version(ctx)
	if err != nil {
		return "", fmt.Errorf("asking the node its Talos version: %w", err)
	}

	return versionTag(resp), nil
}

// InstalledNodeVersion asks a node that has ALREADY TAKEN ITS CONFIG for its
// Talos version, over the authenticated API.
//
// The same question NodeVersion asks and the same "" contract, differing only
// in which client can reach the node. It exists because the version guard runs
// at step 3, BEFORE Up's already-configured branch at step 5 — so a resumed
// bring-up still needs a version, and the maintenance API that NodeVersion uses
// is gone for good once a node has installed.
//
// IT POLLS, and it is the only question in this file that does. NodeVersion
// above is asked immediately after WaitMaintenance has just proved the node
// answers; this one is the FIRST call a resumed bring-up makes, with nothing
// ahead of it that waited for anything. A single dropped packet therefore ended
// the whole run — measured against a healthy node, from a workstation on Wi-Fi.
//
// The retry is bounded rather than generous on purpose: this is not a wait for
// a node to become ready, it is a question to a node that is supposed to be
// ready already. A node that cannot answer within the budget is a real failure
// and the caller should hear about it.
//
// talosconfig is secret and is neither logged nor placed in an error.
func InstalledNodeVersion(ctx context.Context, talosconfig []byte, endpoint string, timeout time.Duration) (string, error) {
	c, err := AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return "", err
	}

	defer c.Close() //nolint:errcheck

	var version string

	if err := waitFor(ctx, timeout, "the installed node at "+endpoint+" to report its Talos version",
		func(ctx context.Context) error {
			resp, err := c.Version(ctx)
			if err != nil {
				return fmt.Errorf("asking the installed node its Talos version: %w", err)
			}

			version = versionTag(resp)

			return nil
		}); err != nil {
		return "", err
	}

	return version, nil
}

// versionTag picks a version tag out of a Version reply, or "" when the reply
// carries none.
//
// It is split out of NodeVersion because this loop IS the "never errors on an
// unidentifiable version" contract above, and a pure function is the only way
// to pin it: reaching these branches through NodeVersion would take a fake
// apid, so left inline they are asserted by nothing but a doc comment.
func versionTag(resp *machineapi.VersionResponse) string {
	// One node, so one message — but ranging costs nothing and a nil Messages
	// slice is a real reply shape rather than a panic.
	for _, m := range resp.GetMessages() {
		if tag := m.GetVersion().GetTag(); tag != "" {
			return tag
		}
	}

	return ""
}

// Disk is one of a node's disks, reduced to what choosing an install target
// needs. It is a struct of our own rather than machinery's DiskSpec so the
// table below cannot drift with a field we never render.
type Disk struct {
	ID         string
	Serial     string
	Model      string
	Size       string
	Transport  string
	WWID       string
	Rotational bool
	Readonly   bool
	CDROM      bool
}

// ListDisks asks a maintenance-mode node what disks it has.
//
// Same COSI call TestAgainstARealNode has made against a real node since the
// bring-up branch (client_test.go:915); this is that call given an exported
// caller, not new capability.
func ListDisks(ctx context.Context, endpoint string) ([]Disk, error) {
	c, err := MaintenanceClient(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	defer c.Close() //nolint:errcheck

	list, err := safe.StateListAll[*blockres.Disk](ctx, c.COSI)
	if err != nil {
		return nil, fmt.Errorf("listing the node's disks: %w", err)
	}

	return toDisks(slices.Collect(list.All())), nil
}

// toDisks reduces machinery's disk resources to the fields the table renders,
// in a deterministic order.
//
// It is split out of ListDisks for the same reason versionTag is split out of
// NodeVersion: reaching it through ListDisks takes a node, so left inline the
// only half of that function with any decisions in it would be asserted by
// nothing. A swapped pair in the literal below still compiles and still prints
// a table — one whose SERIAL column shows models, which is precisely the table
// a human cannot act on that this whole chain exists to prevent.
func toDisks(ds []*blockres.Disk) []Disk {
	out := make([]Disk, 0, len(ds))

	for _, d := range ds {
		s := d.TypedSpec()
		out = append(out, Disk{
			ID: d.Metadata().ID(), Serial: s.Serial, Model: s.Model,
			Size: s.PrettySize, Transport: s.Transport, WWID: s.WWID,
			Rotational: s.Rotational, Readonly: s.Readonly, CDROM: s.CDROM,
		})
	}

	// COSI's list order is not a promise. The table is read by a human copying
	// a serial out of it, and a table that reshuffles between two runs of adopt
	// is one they have to re-read from the top every time.
	slices.SortFunc(out, func(a, b Disk) int { return strings.Compare(a.ID, b.ID) })

	return out
}

// diskRow is shared by the header and the rows beneath it because they are one
// table: widen a column in only one of them and the header slides off its
// values with nothing to fail.
const diskRow = "  %-8s %-24s %-22s %-10s %s\n"

// FormatDisks renders the table that is the REMEDY for both refusals below.
// Without talosctl there is no other way to learn a serial, so this is not
// diagnostic decoration — it is the only path forward.
func FormatDisks(disks []Disk) string {
	var b strings.Builder

	fmt.Fprintf(&b, diskRow, "DEVICE", "SERIAL", "MODEL", "SIZE", "NOTES")

	for _, d := range disks {
		var notes []string
		// READONLY FIRST, and it is the one that matters: the medium you booted
		// from presents as a read-only virtio-blk device rather than a cdrom.
		if d.Readonly {
			notes = append(notes, "readonly — probably the medium you booted from")
		}

		if d.CDROM {
			notes = append(notes, "cdrom")
		}

		if d.Rotational {
			notes = append(notes, "rotational")
		}

		if d.Transport != "" {
			notes = append(notes, d.Transport)
		}

		// QUOTED, because a WWID is the one value in this table a human is
		// asked to copy that can contain RUNS OF SPACES — a real one off a USB
		// bridge reads `t10.SSK     PCIe581         DD0000000000000C`, and
		// unquoted there is nothing to say whether the gaps are part of the
		// value or the table's own padding. Collapsing them yields a selector
		// that matches nothing, which Talos reports as a hang.
		if d.Serial == "" && d.WWID != "" {
			notes = append(notes, fmt.Sprintf("no serial; wwid %q", d.WWID))
		}

		serial := d.Serial
		if serial == "" {
			serial = "(none)"
		}

		fmt.Fprintf(&b, diskRow,
			d.ID, serial, d.Model, d.Size, strings.Join(notes, ", "))
	}

	return b.String()
}

// DiskRef names ONE disk by an identity that disk actually reports.
//
// IT EXISTS BECAUSE A SERIAL IS NOT UNIVERSAL. USB bridges routinely report
// none — on this repo's own target machine exactly one disk of six has a
// serial, and the install target is not it. A node whose install target cannot
// be named is a node this tool cannot adopt, so the WWID beside it in
// FormatDisks's NOTES column has to be nameable too.
//
// A STRUCT RATHER THAN TWO ADJACENT STRING PARAMETERS, for the reason toDisks
// gives about its own literal: `RequireDisk(disks, serial, wwid, what)` is
// three strings in a row, a transposed pair still compiles, and the result is a
// selector that matches nothing — which Talos reports as a hang, not an error.
// Naming the fields is what makes that transposition unwriteable.
//
// EXACTLY ONE is set. Validate says so, and the callers that read a manifest
// call it before a node is dialled, so "both" and "neither" are refusals over
// the file rather than ten minutes spent discovering them.
type DiskRef struct {
	Serial string
	WWID   string
	// DevPath names the target by device path instead of selecting it by an
	// attribute. It exists for a device that HAS no stable attribute to select
	// on: an md array carries no serial and no WWID, so a selector can never
	// name one, and Talos consults machine.install.disk only when the selector
	// is absent entirely.
	DevPath string
}

func (r DiskRef) IsZero() bool { return r.Serial == "" && r.WWID == "" && r.DevPath == "" }

// Validate refuses a ref that names a disk twice or not at all.
//
// `what` is the caller's word for this disk ("install target"), so the refusal
// reads in the caller's terms rather than this type's.
func (r DiskRef) Validate(what string) error {
	named := 0
	for _, v := range []string{r.Serial, r.WWID, r.DevPath} {
		if v != "" {
			named++
		}
	}

	if named > 1 {
		return fmt.Errorf("the %s is named more than once — serial %q, wwid %q, devPath %q — and they select "+
			"differently\n\n  keep the one you copied out of this node's disk table and delete the others",
			what, r.Serial, r.WWID, r.DevPath)
	}

	return nil
}

// String renders the ref the way the disk table labels it, so a refusal quoting
// it can be matched against a column by eye.
func (r DiskRef) String() string {
	switch {
	case r.DevPath != "":
		return r.DevPath
	case r.Serial != "":
		return fmt.Sprintf("serial %q", r.Serial)
	case r.WWID != "":
		return fmt.Sprintf("wwid %q", r.WWID)
	default:
		return "no serial or wwid"
	}
}

// Match reports whether d is the disk this ref names.
//
// EXACT, not EqualFold, and deliberately unlike RequireLink's MAC comparison: a
// MAC has one canonical form and differs only in case between a switch UI and
// the kernel, while a serial and a WWID are opaque vendor strings whose case
// carries meaning. Folding them would let two distinct disks compare equal.
func (r DiskRef) Match(d Disk) bool {
	switch {
	case r.Serial != "":
		return d.Serial == r.Serial
	case r.WWID != "":
		return d.WWID == r.WWID
	default:
		return false
	}
}

// RequireDisk refuses unless ref names a disk this node actually has.
//
// TWO refusals share ONE table, because they are the same remedy. The empty
// case is a first run. The unmatched case is a TYPO, which is the realistic
// failure and the expensive one: Talos with a selector matching nothing
// installs nowhere and reports it as a hang, with nothing pointing at a
// mistyped serial. A node with no disks at all is the third refusal and does
// NOT share that remedy — see below.
//
// Auto-selecting by size was rejected — config.go already calls that "a coin
// flip once there are two large disks", and on hardware the losing side
// overwrites a disk that may hold data, which is the one failure here that
// re-running cannot repair.
func RequireDisk(disks []Disk, ref DiskRef, what string) error {
	// Before either refusal, because both of them end by telling the reader to
	// pick a serial out of the table — and with no disks the table is a header
	// over nothing. The remedy is not "choose one", it is "this node has
	// nothing to install onto".
	if len(disks) == 0 {
		return fmt.Errorf("the node reports no disks at all, so no %s can be chosen\n\n"+
			"  a serial cannot be picked from an empty list. Check that this machine has a\n"+
			"  drive its kernel can see, then run adopt again", what)
	}

	// BOTH COLUMNS ARE OFFERED, because on some machines only one of them is
	// populated: a disk with no serial can still be named by the WWID printed
	// in its NOTES, and that is the only way to name it at all.
	if ref.IsZero() {
		return fmt.Errorf("nothing given to name the %s, and it cannot be guessed\n\n"+
			"this node's disks:\n\n%s\n"+
			"  put one of those serials in the machine file, then run adopt again — or, for a\n"+
			"  disk whose SERIAL reads (none), the wwid printed in its NOTES instead",
			what, FormatDisks(disks))
	}

	if err := ref.Validate(what); err != nil {
		return err
	}

	for _, d := range disks {
		if ref.Match(d) {
			return nil
		}
	}

	return fmt.Errorf("the %s %s matches none of this node's disks\n\n"+
		"this node's disks:\n\n%s\n"+
		"  an identity that matches nothing is almost always a typo. Talos does not "+
		"report it as one:\n  it installs nowhere and the bring-up hangs.",
		what, ref, FormatDisks(disks))
}

// Link is one of a node's network interfaces, reduced to what CHOOSING one
// needs. A struct of our own rather than machinery's LinkStatusSpec, for the
// reason Disk is one: the table below cannot drift with a field we never render.
type Link struct {
	ID            string
	HardwareAddr  string
	PermanentAddr string
	Driver        string
	OperState     string
	Carrier       bool
	Physical      bool
}

// ListLinks asks a maintenance-mode node what network interfaces it has.
//
// The same call shape as ListDisks, against the same maintenance client. Whether
// maintenance mode authorizes this resource is asserted in TestAgainstARealNode
// rather than assumed here — see that test for the fallback.
func ListLinks(ctx context.Context, endpoint string) ([]Link, error) {
	c, err := MaintenanceClient(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	defer c.Close() //nolint:errcheck

	list, err := safe.StateListAll[*netres.LinkStatus](ctx, c.COSI)
	if err != nil {
		return nil, fmt.Errorf("listing the node's network links: %w", err)
	}

	return toLinks(slices.Collect(list.All())), nil
}

// toLinks reduces machinery's link resources to the fields the table renders,
// in a deterministic order.
//
// Split out of ListLinks for the reason toDisks is split out of ListDisks:
// reaching it through ListLinks takes a node, so the only half of that function
// with any decisions in it would be asserted by nothing. A swapped pair here
// still compiles and still prints a table — one whose MAC column shows drivers.
func toLinks(ls []*netres.LinkStatus) []Link {
	out := make([]Link, 0, len(ls))

	for _, l := range ls {
		s := l.TypedSpec()

		// PHYSICAL ONLY. Talos reports loopback, bonds, bridges and vlans
		// through the same resource, and none of them is a NIC an operator can
		// plug a cable into. Physical() is machinery's own predicate for it.
		if !s.Physical() {
			continue
		}

		out = append(out, Link{
			ID:            l.Metadata().ID(),
			HardwareAddr:  net.HardwareAddr(s.HardwareAddr).String(),
			PermanentAddr: net.HardwareAddr(s.PermanentAddr).String(),
			Driver:        s.Driver,
			OperState:     s.OperationalState.String(),
			// CARRIER, not "up". A link can be administratively up with no
			// cable in it, and that is exactly the NIC an operator picks by
			// mistake on a two-port box.
			Carrier:  s.LinkState,
			Physical: true,
		})
	}

	// COSI's list order is not a promise, and this table is read by a human
	// copying a MAC out of it.
	slices.SortFunc(out, func(a, b Link) int { return strings.Compare(a.ID, b.ID) })

	return out
}

// linkRow is shared by the header and the rows beneath it because they are one
// table: widen a column in only one and the header slides off its values with
// nothing to fail.
const linkRow = "  %-10s %-19s %-10s %-8s %s\n"

// FormatLinks renders the table that is the REMEDY for the refusals below.
// Without talosctl there is no other way to learn this node's MACs, so it is
// not diagnostic decoration — it is the only path forward.
func FormatLinks(links []Link) string {
	var b strings.Builder

	fmt.Fprintf(&b, linkRow, "DEVICE", "MAC", "DRIVER", "STATE", "NOTES")

	for _, l := range links {
		var notes []string

		if l.Carrier {
			notes = append(notes, "carrier — a cable is in it")
		} else {
			notes = append(notes, "NO CARRIER — nothing plugged in, or the far end is down")
		}

		// Printed only when it DIFFERS. Equal is the normal case and a second
		// identical MAC in the row is noise a reader has to rule out.
		if l.PermanentAddr != "" && l.PermanentAddr != l.HardwareAddr {
			notes = append(notes, "permanent "+l.PermanentAddr)
		}

		fmt.Fprintf(&b, linkRow, l.ID, l.HardwareAddr, l.Driver, l.OperState, strings.Join(notes, ", "))
	}

	return b.String()
}

// RequireLink refuses unless hardwareAddr names a link this node has AND that
// link has carrier.
//
// THREE refusals, and the first two share one table because they are the same
// remedy. Empty is a first run. Unmatched is a typo — the realistic failure and
// the expensive one, because Talos with a selector matching nothing configures
// nothing and the node comes back with no address at all. No carrier is the
// third and it is the one this repo's target machine invites: two ports, one
// cabled, and the wrong choice is invisible until the install reboot.
func RequireLink(links []Link, hardwareAddr string) error {
	// Before any of them, because every refusal below ends by telling the
	// reader to copy a MAC out of the table, and with no links that table is a
	// header over nothing.
	if len(links) == 0 {
		return errors.New("the node reports no physical network links at all, so no NIC can be chosen\n\n" +
			"  a MAC cannot be picked from an empty list. Check that this machine has an\n" +
			"  ethernet interface its kernel can see, then run adopt again")
	}

	if hardwareAddr == "" {
		return fmt.Errorf("no hardwareAddr given for the static network, and one cannot be guessed\n\n"+
			"this node's links:\n\n%s\n"+
			"  put the MAC of the cabled one in spec.baremetal.network.hardwareAddr, then run\n"+
			"  adopt again", FormatLinks(links))
	}

	for _, l := range links {
		// EqualFold, because a MAC copied from a switch UI or a datasheet is
		// upper case and the node reports lower. Refusing that is a refusal
		// over presentation, and the remedy would read as a typo hunt.
		if !strings.EqualFold(l.HardwareAddr, hardwareAddr) {
			continue
		}

		if !l.Carrier {
			return fmt.Errorf("hardwareAddr %s is this node's %s, which has NO CARRIER\n\n"+
				"this node's links:\n\n%s\n"+
				"  nothing is plugged into it, or the far end is down. Configured anyway, the\n"+
				"  node installs, reboots, brings up a link that cannot pass traffic, and is\n"+
				"  never heard from again.", hardwareAddr, l.ID, FormatLinks(links))
		}

		return nil
	}

	return fmt.Errorf("hardwareAddr %s matches none of this node's links\n\n"+
		"this node's links:\n\n%s\n"+
		"  a MAC that matches nothing is almost always a typo. Talos does not report it as\n"+
		"  one: it configures no interface, and the node comes back with no address.",
		hardwareAddr, FormatLinks(links))
}
