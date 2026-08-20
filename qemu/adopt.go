package qemu

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/coglative/talos-in-qemu/cluster"
	"github.com/coglative/talos-in-qemu/driverkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// adoptMaintenanceTimeout covers a node that may still be booting when adopt is
// run. It is generous because the operator has just walked over and pressed a
// power button, and firmware on real hardware is slower than QEMU's.
const adoptMaintenanceTimeout = 10 * time.Minute

// specBaremetal answers TWO questions about spec.baremetal, and they are
// different questions: is the block PRESENT, and is it WELL-FORMED.
//
// Presence is the discriminator, not a mode field. A machine either describes
// hardware that already exists or a guest this tool creates, and there is no
// third thing — so an explicit `provider:` string would be a second source of
// truth that could contradict the block beside it.
//
// ONLY PRESENCE MAY DECIDE DESTRUCTIVENESS, which is why the two answers are
// returned separately. This measures presence with NestedFieldNoCopy's found
// rather than a successful map cast, because a successful cast answers the
// other question. The block is unschematised today, so a scalar (`baremetal:
// yes`) or a bare `baremetal:` that YAML decodes to null reaches here intact;
// asking NestedMap about either gets nil, and nil read as "absent" makes a
// machine on a desk sweepable, destroyable and its talosconfig removable. A
// malformed block is a typo in a manifest — it is not consent to power-cycle
// hardware, so it counts as present and the caller refuses to touch it.
//
// block is nil exactly when the machine is a VM (present false) or the block
// is malformed (present true) — the caller distinguishes those two by present.
// An empty `baremetal: {}` is well-formed and yields a non-nil empty map: it
// fails later, on the fields it is missing, which is the honest complaint.
func specBaremetal(m *unstructured.Unstructured) (block map[string]interface{}, present bool) {
	v, found, err := unstructured.NestedFieldNoCopy(m.Object, "spec", "baremetal")
	if err != nil || !found {
		// err here means spec itself is not a map, so it holds no baremetal
		// block to be wrong about.
		return nil, false
	}
	block, _ = v.(map[string]interface{})
	return block, true
}

// isBaremetal is the guard the four destructive driver methods key on. It asks
// only whether the block is THERE — see specBaremetal for why reading it is a
// separate question, and why a malformed block answers true here.
func isBaremetal(m *unstructured.Unstructured) bool {
	_, present := specBaremetal(m)
	return present
}

// baremetalFields is the read side: the block's fields, empty for a VM AND for
// a machine whose block is malformed. Every caller of this is a field read that
// has a sane empty answer; the one place a malformed block must be named out
// loud is adoptMachine, which says so before it reads anything.
func baremetalFields(m *unstructured.Unstructured) map[string]interface{} {
	block, _ := specBaremetal(m)
	return block
}

// The two endpoints of an adopted node. NO FORWARD IS INVOLVED: apid and
// kube-apiserver serve their own default ports on the node itself, so these are
// the same constants the guest side uses, applied to a real address.
func baremetalTalosEndpoint(m *unstructured.Unstructured) string {
	if a := str(baremetalFields(m)["maintenanceEndpoint"], ""); a != "" {
		return fmt.Sprintf("%s:%d", a, talosAPIGuestPort)
	}
	return ""
}

// baremetalNetwork reads spec.baremetal.network, or nil when there is none.
//
// nil is a REAL ANSWER — DHCP, which is what every node had before this block
// existed. A malformed block is not: a scalar `network: 192.168.2.10/24` reads
// as every field empty, and a config generated from that would name no
// interface at all.
func baremetalNetwork(m *unstructured.Unstructured) (*cluster.Network, error) {
	raw, present := baremetalFields(m)["network"]
	if !present || raw == nil {
		return nil, nil
	}

	block, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec.baremetal.network is not a block of fields\n\n"+
			"  it must be a mapping:\n\n    network:\n      address: 192.168.2.10/24\n"+
			"      gateway: 192.168.2.1\n      nameservers: [1.1.1.1]\n"+
			"      hardwareAddr: 84:47:09:47:35:f9\n\n  (%s)", m.GetName())
	}

	n := &cluster.Network{
		Address:      str(block["address"], ""),
		Gateway:      str(block["gateway"], ""),
		HardwareAddr: str(block["hardwareAddr"], ""),
	}

	// A non-string entry becomes "", which cluster.CheckNetwork refuses as "not
	// an address" — the same complaint it would make about a typo, which is the
	// honest one for a value that is not a resolver either way.
	if list, ok := block["nameservers"].([]interface{}); ok {
		for _, v := range list {
			n.Nameservers = append(n.Nameservers, str(v, ""))
		}
	}

	return n, nil
}

// baremetalInstalledAddr is the BARE address a client dials once the node has
// installed: the static address when there is one, the maintenance address
// otherwise.
//
// The parse error is DISCARDED and the maintenance address stands in, which is
// safe for exactly one reason: adopt refuses an unparseable block up front, so
// the only caller that can reach the fallback is Observe — on a manifest adopt
// would never have accepted. Observe COULD carry an error — it returns one —
// and that is exactly why this must not: an error out of a driver method is
// retried on every tick forever and, on the delete path, wedges a finalizer.
// See the three guards below, which exist for the same reason. A typo in a
// manifest is not consent to make a TalosMachine undeletable.
func baremetalInstalledAddr(m *unstructured.Unstructured) string {
	maintenance := str(baremetalFields(m)["maintenanceEndpoint"], "")

	n, err := baremetalNetwork(m)
	if err != nil || n == nil {
		return maintenance
	}

	ip, err := n.IP()
	if err != nil {
		return maintenance
	}

	return ip
}

// baremetalInstalledEndpoint is where the node answers AFTER the install.
func baremetalInstalledEndpoint(m *unstructured.Unstructured) string {
	if a := baremetalInstalledAddr(m); a != "" {
		return fmt.Sprintf("%s:%d", a, talosAPIGuestPort)
	}

	return ""
}

// baremetalKubeEndpoint is the kubeconfig's server, and it follows the address
// the node KEEPS. A kubeconfig written against the maintenance address is a
// file that stops working at the first reboot, on a node that is otherwise fine.
func baremetalKubeEndpoint(m *unstructured.Unstructured) string {
	if a := baremetalInstalledAddr(m); a != "" {
		return fmt.Sprintf("https://%s:%d", a, kubeAPIGuestPort)
	}

	return ""
}

// refuseWrongSubstrate rejects a verb applied to the substrate it cannot serve.
//
// The four VM verbs are not merely inapplicable to hardware, they are unsafe on
// it. `destroy` is the sharp one: its contract is to take the entire SCC, and
// on a machine it did not create it can take only the artifacts — including the
// sole talosconfig that reaches a node it has no way to destroy. A verb that
// half-honours its contract while deleting the only credential to the surviving
// machine is worse than one that refuses.
func refuseWrongSubstrate(m *unstructured.Unstructured, verb string) error {
	bm := isBaremetal(m)

	if verb == "adopt" {
		if bm {
			return nil
		}
		return fmt.Errorf("`tinq adopt` needs spec.baremetal (the node's address and its "+
			"disk serials); %s describes a VM, so `tinq up` is the verb that builds it",
			m.GetName())
	}

	if !bm {
		return nil
	}

	return fmt.Errorf("`tinq %s` cannot act on %s: it has spec.baremetal, so it is a machine "+
		"this tool did not create and cannot power-cycle\n\n  `tinq adopt` is the verb that "+
		"brings it up\n\n(there is no `forget` verb yet, so clearing its state directory is "+
		"`rm -rf` for now)", verb, m.GetName())
}

// The three guards below are refuseWrongSubstrate for the CONTROLLER's path.
//
// refuseWrongSubstrate covers the four CLI verbs, and the controller reaches
// the very same driver methods without passing any of them: driverkit's
// reconcile handles a deletion timestamp BEFORE it Observes, so `kubectl delete
// talosmachine bm0` lands in Destroy directly. The refusals therefore have to
// exist twice, in two shapes — a CLI verb refuses by erroring at the operator,
// a driver method cannot, because an error there is retried on every tick
// forever and, on the delete path, wedges a finalizer.

// forgetBaremetal is Destroy for hardware: it removes NOTHING and succeeds.
//
// Destroy's contract is to take the entire SCC, and returning nil without
// taking it is normally the exact leak this design exists to prevent. Here the
// contract is satisfied differently, because THE SCC DOES NOT CONTAIN THE
// MACHINE: this driver did not create the node, cannot power it off and cannot
// wipe its disks. What sits in the state dir is not the resource, it is the
// CREDENTIAL to it — the talosconfig and kubeconfig for a node that left
// maintenance mode the moment it was adopted and can therefore never be
// adopted again.
//
// So the choice is not "sweep or leak", it is which direction to be wrong in:
// strand a credential for a machine that outlives its registration, or delete
// the only key to a machine still running on a desk hosting the cluster. The
// first is one `rm -rf` away; the second is a reinstall. Deleting a
// REGISTRATION must not delete the machine's credential.
//
// nil rather than an error is required as well as correct: an error BLOCKS
// deletion, so `kubectl delete talosmachine` would hang on the finalizer
// forever for a resource this driver has no teardown work to do on at all.
func forgetBaremetal(m *unstructured.Unstructured, dir string) error {
	log.Printf("%s has spec.baremetal: FORGETTING it, not destroying it. The node stays up, "+
		"its disks stay installed, and nothing under %s was removed — the talosconfig there "+
		"is the only credential that reaches it, and this driver cannot make another. "+
		"Delete that directory yourself once the node is genuinely gone.", m.GetName(), dir)
	return nil
}

// ignoreBaremetalOp is Create and Stop for hardware: change nothing, say so,
// return nil.
//
// nil, not an error, and the reason is the reconcile loop rather than
// politeness. An error is retried every tick and this one could never clear,
// because the driver has no way to alter what it observes — a tick that always
// fails is noise that teaches an operator to stop reading the log. Create in
// particular would fail in resolveImage, which is a baffling thing to print
// about a machine that has no image because it is not a VM.
//
// nil converges instead: observeBaremetal reports Running, so plan() never
// asks for Create again. Stop stays reachable through spec.powerState:
// Stopped, a request this driver cannot serve on hardware; it then logs this
// line each tick and changes nothing, which is the honest outcome.
func ignoreBaremetalOp(m *unstructured.Unstructured, op string) error {
	log.Printf("%s has spec.baremetal: refusing to %s it — this driver did not create the node "+
		"and cannot power-cycle it; `tinq adopt` is the verb that brings it up",
		m.GetName(), op)
	return nil
}

// observeBaremetal is Observe for hardware: Running, always.
//
// Running is the least wrong of the three. Absent and Stopped are both answers
// about a FILE — system.qcow2, which a machine on a desk does not have — and
// both read downstream as "not up yet", which is precisely the reading that
// has plan() call Create on hardware. Running is the only state that converges
// the controller to doing NOTHING, and that is the whole of what this driver
// truthfully knows here: it did not create this node, it cannot power-cycle
// it, there is no work.
//
// It is NOT a liveness claim and must not be read as one. A truthful liveness
// answer costs a dial of the node, and Observe is host-side, read-only and run
// every tick by contract. status carries the endpoint so the operator can ask
// the node itself, which is the only thing that can answer.
//
// THE PRICE IS PAID IN Ready, and it is wider than a node that was adopted and
// later powered off. Nothing is stat'ed here — not a state dir, not a
// talosconfig — so a TalosMachine carrying spec.baremetal reports Ready=True
// from the moment it is applied, before `tinq adopt` has ever been run against
// it and whether or not the address in spec.baremetal.maintenanceEndpoint has
// anything behind it. driverkit's Observe contract records the same exception
// from the other side. Reading Ready as "this node is serving" is wrong for hardware in
// both directions; the endpoint in status is what to ask instead.
//
// No pid: this process did not start that node and holds no handle on it — the
// same honesty adopt's Boot func uses when it returns 0.
func observeBaremetal(m *unstructured.Unstructured, dir string) (driverkit.State, map[string]interface{}, error) {
	return driverkit.Running, map[string]interface{}{
		"stateDir": dir, "apiEndpoint": baremetalInstalledEndpoint(m),
	}, nil
}

// kernelCmdlineHint explains a maintenance-wait timeout for a machine that
// declares a static address, and prints the kernel command line that fixes it.
//
// ONLY on the timeout, because that is the only moment it helps. adopt can run
// at all only once the node is already reachable, which means this line was
// already typed correctly — printing it on a successful run is noise on every
// run where nothing is wrong.
//
// The device field renders as the placeholder `<your-nic>` for the operator to
// replace, and the HOSTNAME field is the one left blank. The kernel wants an
// interface NAME and the manifest holds a MAC, which is the one cost of
// selecting the NIC by a stable identity. Blanking the device instead would
// apply the line to EVERY interface, which on this repo's two-port target
// configures the port with no cable in it. Three of the four values still come
// from the file, including the netmask, whose arithmetic is what gets typed
// wrong on a /26.
func kernelCmdlineHint(err error, n *cluster.Network) error {
	if n == nil {
		return err
	}

	// A block this malformed was already refused by CheckNetwork before
	// anything dialled, so this arm is unreachable through adopt. Returning the
	// original failure is still the right answer: a hint is decoration, and
	// decoration must never replace the error it decorates.
	prefix, perr := netip.ParsePrefix(n.Address)
	if perr != nil {
		return err
	}

	mask := net.IP(net.CIDRMask(prefix.Bits(), 32)).String()

	return fmt.Errorf("%w\n\n"+
		"This machine declares a STATIC address, so the segment it sits on probably serves\n"+
		"no DHCP — and a node booted from the ISO then has no address at all. There is\n"+
		"nothing here to reach until you give it one.\n\n"+
		"The ISO's kernel takes one on its command line. At the GRUB menu press `e`,\n"+
		"append this to the linux line, then Ctrl-X:\n\n"+
		"  ip=%s::%s:%s::<your-nic>:off\n\n"+
		"  fields: client::gateway:netmask:hostname:device:autoconf\n"+
		"  <your-nic> is the interface NAME, e.g. enp1s0 — the kernel wants a name where\n"+
		"  this machine file holds a MAC, and the node's console lists both.\n\n"+
		"That configures the MAINTENANCE boot ONLY. The installed system writes its own\n"+
		"command line and inherits nothing from the ISO, which is what the network block\n"+
		"in this machine file exists to carry.",
		err, prefix.Addr(), n.Gateway, mask)
}

// adoptMachine is the `adopt` verb: bring up a node this tool did not create.
//
// It does NOT go through driverkit. Observe/Create/Stop/Destroy all describe a
// resource this program owns the lifecycle of, and none of the four has an
// honest implementation for a machine on a desk with no power control.
//
// Everything before cluster.Up is a PRE-FLIGHT that a QEMU bring-up does not
// need: the version and the disks both come from the node, so both require a
// maintenance-mode node to already be answering.
func adoptMachine(ctx context.Context, d *hvf, path string) error {
	m, err := readMachine(path)
	if err != nil {
		return err
	}

	if err := refuseWrongSubstrate(m, "adopt"); err != nil {
		return err
	}

	// PRESENT IS NOT THE SAME AS READABLE. refuseWrongSubstrate has just
	// established the block is there, which is all the driver guards need; adopt
	// is the one caller that goes on to READ it, so it is the one caller that
	// has to care whether there is anything to read. Saying so here is the
	// difference between a manifest typo and a pile of "required" errors about
	// fields that were never going to be found.
	spec, _ := specBaremetal(m)
	if spec == nil {
		return fmt.Errorf("%s has spec.baremetal, but it is not a block of fields — a scalar "+
			"or an empty `baremetal:` cannot carry an endpoint or a disk serial\n\n"+
			"  it must be a mapping:\n\n    baremetal:\n      maintenanceEndpoint: 192.168.1.50\n"+
			"      systemDiskSerial: S1", m.GetName())
	}

	endpoint := baremetalTalosEndpoint(m)
	if endpoint == "" {
		return errors.New("spec.baremetal.maintenanceEndpoint is required: it is the address this host " +
			"dials to reach the node while it is in maintenance mode, and with no network block " +
			"it is also where the node answers afterwards")
	}

	// A BARE ADDRESS, and a port in it is a TEN-MINUTE HANG rather than a parse
	// error. The two ports are Talos's own and the helpers above append them,
	// so "10.0.0.5:50000" becomes "10.0.0.5:50000:50000" — measured: the whole
	// maintenance budget spent resolving an address that cannot exist, with one
	// "waiting for the Talos maintenance API" line to explain it. Nothing
	// downstream can tell that apart from a node that has not booted yet.
	//
	// An IPv6 literal is caught here too, and truthfully rather than by
	// accident: baremetalTalosEndpoint cannot bracket one, so a v6 address is
	// unsupported and this is where it should be said.
	if addr := str(spec["maintenanceEndpoint"], ""); strings.Contains(addr, ":") {
		return fmt.Errorf("spec.baremetal.maintenanceEndpoint %q must be a bare address with no port: "+
			"apid's %d and kube-apiserver's %d are Talos's own and are added for you\n\n"+
			"  (an IPv6 literal lands here too, and is not supported yet)",
			addr, talosAPIGuestPort, kubeAPIGuestPort)
	}

	// PARSED AND REFUSED BEFORE ANYTHING IS DIALLED. Every check in
	// CheckNetwork is provable from the file, and the expensive one to discover
	// late is the containment refusal: reaching it after the maintenance wait
	// costs ten minutes for a verdict the manifest already contained.
	network, err := baremetalNetwork(m)
	if err != nil {
		return err
	}

	if err := cluster.CheckNetwork(network, str(spec["maintenanceEndpoint"], "")); err != nil {
		return err
	}

	// Read with the guest's own reader, from the same top-level field: a mirror
	// is a property of the NODE, and hardware needs one for the same reason a
	// VM does. Refused here, before the maintenance wait, for the same reason
	// the network block above is.
	mirrors, err := registryMirrors(m)
	if err != nil {
		return err
	}

	// Same reader as a guest's: a config patch is a property of the node, and
	// hardware wants them as much as a VM does (e.g. an extra CA or resolver).
	patches, err := configPatches(m)
	if err != nil {
		return err
	}

	systemDisk := cluster.DiskRef{
		Serial: str(spec["systemDiskSerial"], ""),
		WWID:   str(spec["systemDiskWWID"], ""),
	}
	dataSerial := str(spec["dataDiskSerial"], "")
	ephemeralMaxSize := str(spec["ephemeralMaxSize"], "")

	// STILL ABOVE MkdirAll, with the endpoint and network refusals, because
	// both of these are provable from the FILE. A refusal that has already
	// carved out a state directory leaves residue named after a typo, and
	// TestAdoptRefusesAnEndpointCarryingAPort pins that property for the
	// refusals that came before these.
	if err := systemDisk.Validate("install target"); err != nil {
		return err
	}

	// TWO ANSWERS TO ONE QUESTION. A data disk puts PVCs on a disk of their
	// own; an EPHEMERAL cap puts them on a slice of the system disk. Silently
	// preferring one would install a layout the operator did not ask for onto
	// a disk they cannot un-overwrite.
	if dataSerial != "" && ephemeralMaxSize != "" {
		return fmt.Errorf("spec.baremetal names TWO places for PVCs to live: dataDiskSerial %q and "+
			"ephemeralMaxSize %q\n\n"+
			"  dataDiskSerial gives PVCs a disk of their own — separate device, separate I/O,\n"+
			"  and it survives the system disk dying.\n\n"+
			"  ephemeralMaxSize carves the SYSTEM disk in two instead. Use it only when there\n"+
			"  is no second disk to give.\n\n"+
			"  delete whichever one you did not mean", dataSerial, ephemeralMaxSize)
	}

	dir := d.dir(m)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}

	installed := baremetalInstalledEndpoint(m)

	// A CREDENTIAL, NOT A STATUS — literally the same read Up makes, which is
	// why it is one function in cluster/ rather than a copy here. Nothing about
	// the node is believed on the strength of this file; an authenticated call
	// is simply impossible without it, so having it is a precondition of asking
	// rather than an answer.
	//
	// What it decides here is which API this node can still serve. Everything
	// in the maintenance pre-flight below — the wait, the disks, the links —
	// needs an API that an installed node stopped serving at its first reboot,
	// and running it anyway spends the whole ten-minute budget to discover
	// that. Up is idempotent and its own failure message says to re-run; this
	// is what makes that advice true, and it stays true only while the two
	// sides agree on what "configured" means.
	talosconfig, configured, err := cluster.ReadTalosconfig(dir)
	if err != nil {
		return err
	}

	// The node's own answer, with the spec as an override for the case Risk 1
	// of the design spec describes: a maintenance-mode node that reports no tag.
	version := str(spec["talosVersion"], "")
	source := "spec.baremetal.talosVersion"

	if configured {
		log.Printf("this machine already has a talosconfig, so the maintenance pre-flight is skipped")

		if version == "" {
			if version, err = cluster.InstalledNodeVersion(ctx, talosconfig, installed, cluster.NodeVersionTimeout); err != nil {
				return err
			}

			source = "the node's authenticated API"
		}
	} else {
		log.Printf("waiting for the Talos maintenance API at %s", endpoint)

		if err := cluster.WaitMaintenance(ctx, endpoint, adoptMaintenanceTimeout); err != nil {
			return kernelCmdlineHint(err, network)
		}

		disks, err := cluster.ListDisks(ctx, endpoint)
		if err != nil {
			return err
		}

		if err := cluster.RequireDisk(disks, systemDisk, "install target"); err != nil {
			return err
		}

		// Checked ONLY when asked for. An absent data disk is a legitimate
		// choice and step 10 announces what it costs; an absent one that was
		// MEANT to be present is a typo, which the same check catches.
		if dataSerial != "" {
			if err := cluster.RequireDisk(disks, cluster.DiskRef{Serial: dataSerial}, "data disk"); err != nil {
				return err
			}
		}

		// ASKED ONLY WHEN THERE IS A STATIC BLOCK. A DHCP node's NIC is Talos's
		// business and naming one for it would be a choice nobody asked for.
		//
		// The refusal that matters here is CARRIER: this repo's target machine
		// has two ports with one cable, and a config pointing at the empty one
		// installs, reboots, brings up a link that cannot pass traffic, and
		// goes silent.
		if network != nil {
			links, err := cluster.ListLinks(ctx, endpoint)
			if err != nil {
				return err
			}

			if err := cluster.RequireLink(links, network.HardwareAddr); err != nil {
				return err
			}
		}

		if version == "" {
			if version, err = cluster.NodeVersion(ctx, endpoint); err != nil {
				return err
			}

			source = "the node's maintenance API"
		}
	}

	return cluster.Up(ctx, cluster.UpOptions{
		ClusterName:      m.GetName(),
		StateDir:         dir,
		TalosEndpoint:    endpoint,
		KubeEndpoint:     baremetalKubeEndpoint(m),
		SystemDisk:       systemDisk,
		DataDiskSerial:   dataSerial,
		EphemeralMaxSize: ephemeralMaxSize,
		TalosVersion:     version,
		VersionSource:    source,
		Substrate:        fmt.Sprintf("baremetal, %s", str(spec["maintenanceEndpoint"], "")),
		// EMPTY BY DEFAULT. Real hardware has a firmware-configured console and
		// usually a display; a console argument derived from THIS host's
		// architecture is a guess, and a wrong one is silent at exactly the
		// boot you would need it for.
		ConsoleArg: str(spec["consoleArg"], ""),
		// The kexec workaround is QEMU-on-macOS-specific. Hardware reboots
		// through its own firmware and has nothing to work around.
		DisableKexec: false,
		// The address the node answers on AFTERWARDS is derived from this by
		// cluster.Up, never configured beside it — see installedEndpoint.
		Network: network,
		// Same field, same reader as a guest's. On hardware the endpoint is a
		// real address with a real certificate, so it is https:// and possibly
		// insecureSkipVerify; the mechanism underneath is identical.
		Registries:    mirrors,
		ConfigPatches: patches,
		// ALREADY RUNNING, by definition — that is what adopt means. Returning
		// a pid of 0 is honest: this process did not start it and has no
		// handle on it.
		Boot: func() (int, error) { return 0, nil },
	})
}
