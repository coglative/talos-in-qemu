// tinq — reconciles TalosMachine into a QEMU virtual machine.
//
// It runs HOST-RESIDENT, not as a pod, because a hardware accelerator is a
// KERNEL API on the machine the VM runs on with no network endpoint: HVF on
// macOS, /dev/kvm on Linux. A controller inside the cluster cannot reach either.
// That is the same shape Sidero's own omni-infra-provider-libvirt uses (a binary
// beside the hypervisor, talking to the control plane over the API). The
// provisioning layer is unaffected — it sees a resource, not a hypervisor.
//
// Which binary, machine type, accelerator and firmware this host needs is
// resolved at RUNTIME by the platform package, not by build tags — see its
// package comment for why.
//
// The GC contract lives in driverkit and is identical for every substrate. What
// is HERE is only what qemu decides for itself: its SCC (process + disk + pflash
// + state dir are ONE unit), where the site tag lives (a path component), and
// how a neutral profile name resolves to a local artifact.
//
// The `hvf` type and the ~/.hvf state root keep their names from when this was
// macOS-only. They are load-bearing — the state path and the
// machine.hvf.fleet.io API group are what installed machines already use — so
// renaming them is a migration, not a rename.
//
// tier: compute uses QEMU user-mode networking, which requires NO ROOT. Root is
// a vmnet requirement, so it arrives with tier fabric-sim, not before.
package qemu

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coglative/talos-in-qemu/cluster"
	"github.com/coglative/talos-in-qemu/driverkit"
	"github.com/coglative/talos-in-qemu/platform"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

type hvf struct {
	stateRoot string
	// Where neutral profile names resolve. Provider config, not claim content
	// (ARCHITECTURE.md D12).
	imageRoot string
	// platform.Detect execs `qemu-system-X -accel help` and walks two registry
	// directories. create() runs on EVERY reconcile tick where Observe reports
	// absent, so a VM that fails to start would re-run the whole probe forever
	// and re-write the multi-line accel diagnostic into a status condition each
	// pass. Host facts do not change while the process runs, so probe once.
	//
	// Deliberately NOT hoisted into main(): destroy must keep working on a host
	// with no usable accelerator. Teardown cannot require a live hypervisor.
	detect func() (*platform.Platform, error)
}

// Main is the CLI entrypoint, called by cmd/tinq. It is a function rather than `func main` so this
// package can be IMPORTED: a package containing func main cannot be, and that -- not any design
// decision -- is the only thing that kept this driver from being bound directly by a controller.
func Main() {
	// driverkit reads --kubeconfig off the STDLIB flagset (flag.Lookup), so it
	// must still be registered there. AddGoFlagSet below adopts it into cobra,
	// which means one flag object serves both: cobra parses it, driverkit reads
	// it. Changing driverkit's signature for a CLI refactor would ripple into
	// every other provider built on the same contract.
	// -install SHORT-CIRCUITS COBRA, deliberately. It runs before any command wiring because it is
	// not a tinq operation: it is how this binary gets to a filesystem where qemu exists. Routing it
	// through cobra would make an image-plumbing concern look like a verb.
	for i, a := range os.Args[1:] {
		if a == "-install" || a == "--install" {
			dest := ""
			if i+2 < len(os.Args) {
				dest = os.Args[i+2]
			}
			if err := installSelf(dest); err != nil {
				fmt.Fprintf(os.Stderr, "tinq: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	driverkit.Kubeconfig()
	// SilenceErrors keeps cobra from printing the error itself; we print it
	// ONCE here. Without this the pair (SilenceErrors, SilenceUsage) makes a bad
	// invocation exit 1 with NO output at all, which is worse than the flags it
	// replaced.
	if err := RootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "tinq: %v\n", err)
		os.Exit(1)
	}
}

// newRootCmd builds the CLI.
//
// VERBS, NOT FLAGS. This was `-apply <file>` / `-destroy <file>` / `-up <file>`
// — three string flags that were really a mode selector, so nothing stopped you
// passing two at once and the help text could not say which combinations meant
// anything. As subcommands the shape is checked by the parser, each verb owns
// its own flags and args, and `tinq up --help` documents one thing.
//
// It also matches the neighbourhood: talosctl, kubectl and the crossplane CLI
// are all cobra, so `tinq up machine.yaml` reads native to anyone who would use
// this.
// RootCmd is exported so an embedder can inspect or reuse the command tree.
func RootCmd() *cobra.Command {
	var stateRoot, imageRoot string
	var interval time.Duration

	root := &cobra.Command{
		Use:   "tinq",
		Short: "Talos Kubernetes nodes as real VMs, driven by a TalosMachine resource",
		Long: "tinq reconciles TalosMachine resources into QEMU virtual machines.\n\n" +
			"Run it with a verb to act on ONE machine read from a file (no control\n" +
			"plane needed), or `tinq controller` to watch resources in a cluster.",
		SilenceUsage:  true, // a runtime failure is not a usage error
		SilenceErrors: true, // we print it ourselves, once
	}

	root.PersistentFlags().StringVar(&stateRoot, "state-root",
		filepath.Join(os.Getenv("HOME"), ".hvf"), "per-machine state root")
	root.PersistentFlags().StringVar(&imageRoot, "image-root",
		filepath.Join(os.Getenv("HOME"), ".hvf", "images"),
		"root for resolving non-absolute spec.image profile names")
	// Adopt driverkit's stdlib flags (--kubeconfig). See main().
	root.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	newDriver := func() (*hvf, error) {
		if err := os.MkdirAll(stateRoot, 0o755); err != nil {
			return nil, fmt.Errorf("state root: %w", err)
		}
		return &hvf{stateRoot: stateRoot, imageRoot: imageRoot,
			detect: sync.OnceValues(platform.Detect)}, nil
	}

	// The standalone verbs are the SAME code path with a different word:
	// standalone() decides, and it runs the identical
	// Observe/Create/Stop/Destroy the controller loop uses. Two ways to build a
	// machine would drift.
	runVerb := func(verb string) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			d, err := newDriver()
			if err != nil {
				return err
			}
			return standalone(cmd.Context(), d, args[0], verb)
		}
	}

	apply := &cobra.Command{
		Use:   "apply <machine.yaml>",
		Short: "Create the VM described by one TalosMachine, then exit",
		Long: "Reconcile ONE TalosMachine read from a file, with no control plane.\n\n" +
			"This exists because of a chicken-and-egg: a controller needs a control\n" +
			"plane to read resources from, and on a fresh laptop the control plane is\n" +
			"the thing you are creating. Re-running is safe — if the VM is already\n" +
			"running this reports it and does nothing.",
		Args: cobra.ExactArgs(1),
		RunE: runVerb("apply"),
	}

	stop := &cobra.Command{
		Use:   "stop <machine.yaml>",
		Short: "Halt the VM but KEEP its disks, then exit",
		Long: "A shutdown, not a teardown. The installed OS and any PVCs survive, and\n" +
			"`tinq up` starts the machine again from the same disks — that distinction\n" +
			"is the only reason this exists beside `destroy`. Idempotent: already\n" +
			"stopped, or never created, is success.\n\n" +
			"`up` is the verb that brings a stopped machine back to a Ready cluster: it\n" +
			"is idempotent, and it skips the steps this machine has already passed\n" +
			"rather than sending it back through maintenance mode, which the installed\n" +
			"system never re-enters. (`tinq apply` starts the VM too, and stops there.)\n\n" +
			"A bootstrapped machine is asked to power itself off over the Talos API,\n" +
			"so its filesystem is quiesced. A machine still in maintenance mode has no\n" +
			"talosconfig to ask with, and QEMU is signalled instead (SIGTERM, then\n" +
			"SIGKILL) — a power cut the guest never learns about, which is safe there\n" +
			"because it holds no applied config and nothing persistent. Either way the\n" +
			"escalation is announced in the log rather than performed silently.",
		Args: cobra.ExactArgs(1),
		RunE: runVerb("stop"),
	}

	destroy := &cobra.Command{
		Use:   "destroy <machine.yaml>",
		Short: "Destroy the VM and its whole state directory, then exit",
		Long: "Takes the entire SCC: the qemu process and everything in the state\n" +
			"directory. NOT RECOVERABLE — the installed OS and any PVCs go with it;\n" +
			"`tinq stop` is the verb that keeps them.\n\n" +
			"Idempotent — already-gone is success, and a merely stopped machine is\n" +
			"destroyed too, since it still has disks to sweep. Works with no usable\n" +
			"accelerator and no reachable node: teardown must not require a live\n" +
			"hypervisor.",
		Args: cobra.ExactArgs(1),
		RunE: runVerb("destroy"),
	}

	up := &cobra.Command{
		Use:   "up <machine.yaml>",
		Short: "Create the VM AND bring it up to a single-node Kubernetes cluster",
		Long: "apply, plus the Talos side: machine config, install, bootstrap,\n" +
			"kubeconfig, and storage — one command from a TalosMachine to a Ready\n" +
			"node.\n\nThe VM half is byte-for-byte what `apply` builds; this adds the\n" +
			"cluster on top.\n\nIdempotent, and safe to re-run: a machine that has\n" +
			"already been configured skips config generation and apply-config, and a\n" +
			"bootstrap the node refuses because etcd exists is a success. That is also\n" +
			"how you restart a machine halted with `tinq stop`.",
		Args: cobra.ExactArgs(1),
		RunE: runVerb("up"),
	}

	adopt := &cobra.Command{
		Use:   "adopt <machine.yaml>",
		Short: "Bring up a Talos node this tool did NOT create",
		Long: "Takes a machine that is already booted into maintenance mode — from a USB\n" +
			"stick, virtual media, or netboot — and drives it to a Ready single-node\n" +
			"cluster using the same ten steps `up` uses.\n\n" +
			"Requires spec.baremetal. Run it once with no systemDiskSerial and it prints\n" +
			"the node's disks and refuses; write one down and run it again.\n\n" +
			"It never powers anything on and never installs without an explicit serial.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := newDriver()
			if err != nil {
				return err
			}
			return adoptMachine(cmd.Context(), d, args[0])
		},
	}

	reconfigure := &cobra.Command{
		Use:   "reconfigure <machine.yaml>",
		Short: "Apply an edited manifest to a machine that is already running",
		Long: "Regenerates this machine's config from its manifest, against the SECRETS\n" +
			"BUNDLE it already has, and applies it over the authenticated API.\n\n" +
			"`up` and `adopt` skip config generation once a machine has a talosconfig,\n" +
			"because regenerating there would mint new certificate authorities and take\n" +
			"away the only credential that reaches the node. This is where a manifest\n" +
			"edit goes instead — adding a registry mirror no longer means wiping a disk.\n\n" +
			"Refuses anything decided when the disk was PARTITIONED: the install target,\n" +
			"the EPHEMERAL cap and the user volume's disk. Talos accepts a config saying\n" +
			"otherwise and does nothing about it, so those still need a wipe.\n\n" +
			"Talos decides per change whether a reboot is required.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := newDriver()
			if err != nil {
				return err
			}
			return reconfigureMachine(cmd.Context(), d, args[0])
		},
	}

	controller := &cobra.Command{
		Use:   "controller",
		Short: "Watch TalosMachine resources in a cluster and reconcile them",
		Long: "The steady-state mode. Once the first node is bootstrapped it can host\n" +
			"the CRD and this binary, and every machine after arrives the normal way.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := newDriver()
			if err != nil {
				return err
			}
			return driverkit.Run(cmd.Context(), driverkit.Config{
				GVR: schema.GroupVersionResource{
					Group: "machine.hvf.fleet.io", Version: "v1alpha1", Resource: "talosmachines",
				},
				Finalizer: "machine.hvf.fleet.io/vm",
				Interval:  interval,
			}, d)
		},
	}
	controller.Flags().DurationVar(&interval, "interval", 5*time.Second, "reconcile interval")

	root.AddCommand(apply, stop, destroy, up, adopt, reconfigure, controller)
	return root
}

// standalone runs one CR through the Driver with no control plane. It is
// deliberately thin: decode, refuse the wrong substrate, Observe, then Create,
// Stop or Destroy — the refusal comes second because a machine this tool did
// not create has no honest answer to any of the three. Every
// decision about WHAT a machine is stays in the driver, so bootstrap and steady
// state cannot disagree.
//
// Create is skipped only when Observe reports Running, so re-running is safe
// and does not start a second qemu against the same state dir. Stopped falls
// through to Create, because there is no live process to collide with and
// Create reuses the disks.
//
// That is NOT the controller's rule, and the difference is user-visible:
// standalone always drives toward Running and NEVER READS spec.powerState. A
// manifest carrying powerState: Stopped boots here — a valid value, silently
// ignored — whereas the controller feeds it to plan and converges on it.
// Deliberate: this is the bootstrap path, run before any control plane exists
// to hold the desired state, and its one job is to get a node up. Once the
// controller owns the resource it reconciles powerState normally. `tinq stop`
// is the verb that halts a machine on this path.
func standalone(ctx context.Context, d *hvf, path, verb string) error {
	m, err := readMachine(path)
	if err != nil {
		return err
	}

	// BEFORE Observe, not after. Observe stats system.qcow2 and would report a
	// machine that is a machine as Absent — a meaningless answer for hardware,
	// and one that reads as "not created yet" to everything downstream.
	if err := refuseWrongSubstrate(m, verb); err != nil {
		return err
	}

	state, status, err := d.Observe(ctx, m)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}

	switch verb {
	case "destroy":
		// Stopped is destroyed along with Running: a machine that is merely
		// stopped still has disks and a state dir to sweep, and skipping it is
		// exactly the residue the SCC rule forbids.
		if state == driverkit.Absent {
			log.Printf("already gone: %s", d.dir(m))
			return nil
		}
		return d.Destroy(ctx, m)
	case "stop":
		// Both early returns exist so a re-run is quiet and cheap rather than
		// merely harmless: Stop already re-Observes and returns nil for
		// anything that is not Running, so without these the operator gets no
		// word on WHY nothing happened — and "nothing to stop" and "already
		// stopped" are different facts. The first means no disks exist; the
		// second means they do and survive.
		if state == driverkit.Absent {
			log.Printf("nothing to stop: %s", d.dir(m))
			return nil
		}
		if state == driverkit.Stopped {
			log.Printf("already stopped: %s", d.dir(m))
			return nil
		}
		return d.Stop(ctx, m)
	case "up":
		return bringUp(ctx, d, m, state, status)
	default:
		if state == driverkit.Running {
			log.Printf("already running: %v", status)
			return nil
		}
		if err := d.Create(ctx, m); err != nil {
			return err
		}
		_, status, err = d.Observe(ctx, m)
		if err != nil {
			return fmt.Errorf("observe after create: %w", err)
		}
		log.Printf("created: %v", status)
		return nil
	}
}

// readMachine loads one TalosMachine from a file and gives it a STABLE identity.
//
// The UID is derived rather than random because it keys the state dir: a
// re-run that minted a new one would orphan the first machine's artifacts and
// build a second beside it. Shared by every file-driven verb so the derivation
// cannot drift between them.
func readMachine(path string) (*unstructured.Unstructured, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal(b, &obj); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	m := &unstructured.Unstructured{Object: obj}
	if m.GetUID() == "" {
		m.SetUID(types.UID(fmt.Sprintf("bootstrap-%s-%s", m.GetNamespace(), m.GetName())))
	}

	return m, nil
}

// The two guest ports a bring-up talks to. They are Talos's, not ours: apid
// serves on 50000 and kube-apiserver on 6443, so these are the guest sides that
// spec.hostForwards has to map onto the host.
const (
	talosAPIGuestPort = 50000
	kubeAPIGuestPort  = 6443
)

// defaultHostAddr is the bind address a forward gets when it names none.
//
// It is read in exactly TWO places — the qemu argument builder that BINDS the
// forward, and hostForward below that DIALS it — and it is a constant so those
// two can never drift apart. A dialled address that disagrees with the bound
// one is not a wrong string, it is a five-minute timeout.
const defaultHostAddr = "127.0.0.1"

// hostForward reports the HOST address and port forwarded to guestPort, or
// ("", 0) when the machine forwards nothing there.
//
// Everything reachable from the host goes through a qemu user-mode forward, so
// a missing entry is not a slow path — it is an address that will never answer.
// cluster.Up refuses an empty endpoint up front rather than spending a wait's
// whole budget discovering that.
//
// THE ADDRESS IS RETURNED, not assumed. qemu binds each forward to its own
// hostAddr and binds it EXCLUSIVELY: with hostAddr set to a LAN address,
// nothing is listening on loopback at all. Returning a hardcoded 127.0.0.1
// here sent every wait to an address that could never answer, and the symptom
// was a full maintenance timeout rather than a connection refusal.
func hostForward(m *unstructured.Unstructured, guestPort int) (string, int) {
	for _, hf := range nestedSlice(m, "spec", "hostForwards") {
		h, _ := hf.(map[string]interface{})
		if toInt(h["guestPort"]) == guestPort {
			return str(h["hostAddr"], defaultHostAddr), toInt(h["hostPort"])
		}
	}
	return "", 0
}

// talosEndpoint is the host side of the Talos API forward, host:port, or "".
func talosEndpoint(m *unstructured.Unstructured) string {
	if a, p := hostForward(m, talosAPIGuestPort); p > 0 {
		return fmt.Sprintf("%s:%d", a, p)
	}
	return ""
}

// kubeEndpoint is the host side of the Kubernetes API forward, as a URL, or "".
//
// It is written into the generated config as the control-plane endpoint AND
// into the kubeconfig, so it has to be the address the HOST can reach — the
// guest's own is unroutable from here without a bridge.
func kubeEndpoint(m *unstructured.Unstructured) string {
	if a, p := hostForward(m, kubeAPIGuestPort); p > 0 {
		return fmt.Sprintf("https://%s:%d", a, p)
	}
	return ""
}

// registryMirrors reads spec.registries, the node's image registry mirrors.
//
// IT REFUSES RATHER THAN SKIPS. The CRD already constrains this list, but the
// apiserver is not in the path a bootstrap run takes: `up` and `adopt` read a
// file straight off disk, so every schema guarantee is absent exactly where
// this is read. A malformed entry silently dropped here is a node that pulls
// from the internet instead — which SUCCEEDS for every public image and fails
// only on the one image that exists nowhere else, long after this file was
// accepted.
//
// The scheme check is the same one the CRD's pattern makes, for the same
// reason and in the other half of the world: containerd rejects a scheme-less
// endpoint at PULL time, on a node that has already installed and rebooted.
func registryMirrors(m *unstructured.Unstructured) ([]cluster.RegistryMirror, error) {
	var out []cluster.RegistryMirror

	for i, raw := range nestedSlice(m, "spec", "registries") {
		e, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("spec.registries[%d] is not a block of fields\n\n"+
				"  each entry must be a mapping:\n\n    registries:\n"+
				"      - host: 10.0.2.2:5000\n        endpoint: http://10.0.2.2:5000\n\n  (%s)",
				i, m.GetName())
		}

		ca, err := registryCA(e)
		if err != nil {
			return nil, fmt.Errorf("spec.registries[%d]: %w (%s)", i, err, m.GetName())
		}

		mirror := cluster.RegistryMirror{
			Host:     str(e["host"], ""),
			Endpoint: str(e["endpoint"], ""),
			CA:       ca,
			// A non-bool reads as false, which is the safe answer for both:
			// one weakens TLS and the other suppresses /v2/, and neither is a
			// thing to switch on because a value could not be parsed.
			InsecureSkipVerify: e["insecureSkipVerify"] == true,
			OverridePath:       e["overridePath"] == true,
		}

		// THE PORT IS PART OF THE HOST. An image tagged 10.0.2.2:5000/app:v1
		// is looked up under "10.0.2.2:5000"; an entry of "10.0.2.2" alone
		// never matches it, and that is a mirror configured, accepted, and
		// never consulted. Not checkable here — a registry on :443 is written
		// without a port, correctly — so it is said rather than enforced.
		if mirror.Host == "" {
			return nil, fmt.Errorf("spec.registries[%d] has no host: it is the FIRST SEGMENT of an "+
				"image reference, port included, e.g. 10.0.2.2:5000 (%s)", i, m.GetName())
		}

		if !strings.HasPrefix(mirror.Endpoint, "http://") && !strings.HasPrefix(mirror.Endpoint, "https://") {
			return nil, fmt.Errorf("spec.registries[%d].endpoint is %q, which has no http:// or "+
				"https:// scheme\n\n"+
				"  the scheme is the plain-HTTP switch, not decoration: http:// is what makes\n"+
				"  containerd speak cleartext to a registry that has no certificate, and there\n"+
				"  is no boolean anywhere that does it instead\n\n  (%s)",
				i, mirror.Endpoint, m.GetName())
		}

		out = append(out, mirror)
	}

	return out, nil
}

// bringUp is the -up verb: create (or adopt) the VM, then hand everything after
// that to cluster.Up, which owns all ten steps and every line of output.
func bringUp(ctx context.Context, d *hvf, m *unstructured.Unstructured, state driverkit.State,
	status map[string]interface{}) error {
	opts, err := upOptions(d, m, state, status)
	if err != nil {
		return err
	}
	return cluster.Up(ctx, opts)
}

// upOptions translates a TalosMachine into what cluster.Up needs.
//
// It is separate from bringUp so it can be ASSERTED without a hypervisor. Every
// field below is a value that would compile just as happily wrong — the state
// dir, the two endpoints, the two disk serials, the resolved image — and each
// one is only visibly wrong minutes into a bring-up, on a node that is by then
// half installed.
//
// The VM half is create(), unchanged and unbranched: -up must not become a
// second way to build a machine. What is HERE is only the translation, and
// package main is the only place that can do it — the serials, the qemu
// forwards and the profile resolution are all its.
func upOptions(d *hvf, m *unstructured.Unstructured, state driverkit.State,
	status map[string]interface{}) (cluster.UpOptions, error) {
	spec, _, _ := unstructured.NestedMap(m.Object, "spec")

	image, err := d.resolveImage(spec)
	if err != nil {
		return cluster.UpOptions{}, err
	}

	// Host facts resolved HERE, because this is the layer that owns QEMU. The
	// three values below are the node facts they imply, and the implication is
	// only valid for a guest: the README requires the image architecture to
	// match the host, which is what makes the host's console argument the
	// guest's console argument. Nothing outside this function may assume it.
	host, err := d.detect()
	if err != nil {
		return cluster.UpOptions{}, err
	}

	// Refused BEFORE the VM is created. A malformed mirror is provable from the
	// file, and discovering it after the boot costs a state dir and a
	// maintenance wait for a verdict this line gives for free.
	mirrors, err := registryMirrors(m)
	if err != nil {
		return cluster.UpOptions{}, err
	}

	// Refused here for the same reason as the mirrors above: a malformed patch
	// is provable from the file, and finding it after the boot costs a state dir
	// and a maintenance wait for a verdict this line gives for free.
	patches, err := configPatches(m)
	if err != nil {
		return cluster.UpOptions{}, err
	}

	// The MACHINE's state dir, never the state root: the artifacts carry the
	// identity they belong to, which is the property that makes -destroy sweep
	// them. Written one level up they would outlive the cluster whose keys
	// they are, and the residue check would not find them.
	dir := d.dir(m)

	return cluster.UpOptions{
		ClusterName:   m.GetName(),
		StateDir:      dir,
		TalosEndpoint: talosEndpoint(m),
		KubeEndpoint:  kubeEndpoint(m),
		// A SERIAL, ALWAYS, on this path: main.go sets `serial=` on the QEMU
		// devices itself, so a guest's disks are named by construction and the
		// WWID alternative a DiskRef also carries has nothing to describe here.
		SystemDisk:     cluster.DiskRef{Serial: DiskSerialSystem},
		DataDiskSerial: dataDiskSerial(spec),

		TalosVersion:  platform.InspectImageVersion(image),
		VersionSource: fmt.Sprintf("%s (ISO volume id)", filepath.Base(image)),
		Substrate:     fmt.Sprintf("%s/%s, %s, %s", host.OS, host.ImageArch, host.Accel, host.QEMUBinary),
		ConsoleArg:    host.ConsoleArg,
		// KEXEC IS DISABLED ON macOS/arm64 ONLY. Talos kexecs straight into the
		// kernel it just installed; under QEMU on macOS that path dies in the
		// guest on arm64 and the node never boots what it installed. Elsewhere
		// it works and it is FASTER, so disabling it more widely is a tax paid
		// for another platform's bug. Upstream gates its own workaround on the
		// target ARCHITECTURE, so an Intel Mac has nothing to work around.
		DisableKexec: host.OS == "darwin" && host.ImageArch == "arm64",
		// spec.registries is NOT in the baremetal exclusion rule, so this same
		// list is read the same way by adopt: a mirror is a property of the
		// node, and only its address differs between a guest and a machine.
		Registries:    mirrors,
		ConfigPatches: patches,

		Boot: func() (int, error) {
			// The same already-running rule `apply` applies, and it is what
			// makes `apply` then `up` work: a VM already sitting in
			// maintenance mode is ADOPTED, not duplicated. Starting a second
			// qemu against one state dir would corrupt the disk it shares.
			//
			// RUNNING, not "not Absent". Stopped MUST fall through to create:
			// it has disks and no process, so there is no pid to adopt —
			// status is the {stateDir} map Observe returns for a stopped
			// machine, toInt(nil) is 0, and cluster.Up would report a VM whose
			// process does not exist and then wait out the whole maintenance
			// budget against an address nothing is listening on. Widening this
			// test is a hang, not a misprint.
			if state == driverkit.Running {
				return toInt(status["pid"]), nil
			}
			return d.create(m, dir)
		},
	}, nil
}

// dir keys state by SITE then UID. The site is IN THE PATH on purpose: artifacts
// must carry the identity they belong to or they cannot be garbage-collected —
// the residue check greps for it, and it is the same property that makes gcp
// labels and aws tags work. UID underneath so a recreated resource never reuses
// a stale directory.
func (h *hvf) dir(m *unstructured.Unstructured) string {
	return filepath.Join(h.stateRoot, driverkit.Str(m, "spec", "site"), string(m.GetUID()))
}

// Observe reports what the HOST says, in three states.
//
// Absent is keyed on system.qcow2 rather than on the state dir, because that
// file is exactly what create() would reuse. Both partial-failure paths then
// land correctly with no special case: a create that died before ensureQcow2
// leaves a dir with no disk and reads Absent, so Create retries; disks made but
// qemu never launched reads Stopped, so Create re-execs.
//
// Running demands a VERIFIED process, not a live pid. Never trust a state file
// alone — talosctl's `cluster show` deserialises state.yaml and reports a
// long-dead cluster as present — and a pidfile is a state file too: after a
// host reboot it can name a live stranger. Reading disk here only ever tells
// Absent from Stopped, and neither claims the machine is usable.
//
// This function is READ-ONLY. Unlinking a stale pidfile here would be tidy and
// is refused: an observer with side effects is how a status call quietly
// becomes a mutation. qemu's -pidfile truncates on next start anyway.
func (h *hvf) Observe(ctx context.Context, m *unstructured.Unstructured) (driverkit.State, map[string]interface{}, error) {
	dir := h.dir(m)

	// Hardware answers first. Everything below this line reasons about
	// system.qcow2, a file a machine on a desk does not have and never will.
	if isBaremetal(m) {
		return observeBaremetal(m, dir)
	}

	if _, err := os.Stat(filepath.Join(dir, "system.qcow2")); err != nil {
		if os.IsNotExist(err) {
			return driverkit.Absent, nil, nil
		}
		return driverkit.Absent, nil, err
	}

	pid := readPid(dir)
	if pid <= 0 || !platform.ProcessMatches(pid, dir) {
		return driverkit.Stopped, map[string]interface{}{"stateDir": dir}, nil
	}

	// talosEndpoint, not a second hand-rolled scan of hostForwards: status's
	// apiEndpoint and the endpoint -up hands cluster.Up are two answers to one
	// question, and nothing but this shared call keeps them equal. The
	// hand-rolled loop also reported "127.0.0.1:0" for an entry with a
	// guestPort and no hostPort — an address, printed as status, that cannot
	// answer.
	return driverkit.Running, map[string]interface{}{
		"pid": int64(pid), "stateDir": dir, "apiEndpoint": talosEndpoint(m),
	}, nil
}

func (h *hvf) Create(ctx context.Context, m *unstructured.Unstructured) error {
	if isBaremetal(m) {
		return ignoreBaremetalOp(m, "create")
	}

	if _, err := h.create(m, h.dir(m)); err != nil {
		return err
	}

	// The installed system writes its OWN kernel cmdline and does not inherit
	// the ISO's console, so the config patch has to name it — and the name is
	// architecture-specific (ttyS0 vs ttyAMA0). The README used to make the
	// reader work that out; we already resolved it, so say it.
	//
	// SCOPED TO Create, not create(). -up calls create() directly, and this
	// line went to stderr between steps 3 and 4 of a transcript that IS the
	// feature — where step 6 already says the same thing, better and in the
	// right place. -apply and the controller stop at a booted VM in
	// maintenance mode and leave the operator to write that patch by hand, so
	// they are the only callers that still need the hint.
	//
	// detect is memoized (sync.OnceValues), so create() has already paid for
	// this and it cannot fail here after succeeding there — the guard exists
	// so a future create() that stops probing does not nil-deref.
	if p, err := h.detect(); err == nil {
		log.Printf("for the install config patch on this host: extraKernelArgs: [%s]", p.ConsoleArg)
	}

	return nil
}

// Stop halts the VM and leaves every artifact in place.
//
// The ladder is deliberate and it escalates LOUDLY. A stop that silently
// SIGKILLs after announcing a graceful shutdown is how you find out months
// later that none of your stops were ever clean.
func (h *hvf) Stop(ctx context.Context, m *unstructured.Unstructured) error {
	if isBaremetal(m) {
		return ignoreBaremetalOp(m, "stop")
	}

	state, _, err := h.Observe(ctx, m)
	if err != nil {
		return err
	}
	if state != driverkit.Running {
		return nil // already stopped, or never existed
	}

	dir := h.dir(m)
	pid := readPid(dir)

	if err := h.shutdownGuest(ctx, m); err != nil {
		log.Printf("graceful shutdown unavailable (%v); falling back to signals", err)
	} else {
		gone, err := waitGone(ctx, pid, dir, gracefulStopTimeout)
		if err != nil {
			// Named, not generic. The guest was ASKED to power off and may well
			// be part-way through doing it; what we no longer know is whether it
			// finished. Saying so is the difference between an operator who
			// re-runs the stop and one who believes the machine is down.
			return fmt.Errorf("stop of %s abandoned while waiting for the guest to power "+
				"off; it may still be running: %w", m.GetName(), err)
		}
		if gone {
			return nil
		}
		log.Printf("guest did not power off within %s; escalating to SIGTERM", gracefulStopTimeout)
	}
	return halt(ctx, pid, dir)
}

const (
	gracefulStopTimeout = 60 * time.Second
	sigtermTimeout      = 5 * time.Second
	// How often waitGone re-asks, and therefore the WORST-CASE latency of a
	// Ctrl-C landing mid-wait. Shortening it makes cancellation crisper and
	// costs darwin a `ps` fork every tick; see waitGone.
	pollInterval = 100 * time.Millisecond
	// The budget for the Shutdown REQUEST, not for the power-off it triggers —
	// that is gracefulStopTimeout, waited out by Stop against the process.
	// Talos answers this RPC and runs its shutdown sequence afterwards, so a
	// reachable guest replies in milliseconds over a loopback forward.
	//
	// It exists because ctx here reaches Stop unbounded (cobra's, or the
	// controller loop's), and a gRPC call is only fail-fast once the channel
	// reports TRANSIENT_FAILURE. A guest whose apid accepts the TCP connection
	// and then never completes the TLS handshake leaves the channel CONNECTING
	// forever, and the call blocks with it — so `tinq stop` on a half-wedged
	// node would hang instead of falling through to the signal ladder. A
	// wedged guest must still be stoppable; that is the failure this bounds.
	shutdownRequestTimeout = 15 * time.Second
)

// shutdownGuest asks the GUEST to power itself off, over the authenticated
// Talos API, so the filesystem is quiesced before the VM goes.
//
// The alternative is what Stop falls back to: signalling the QEMU PROCESS,
// which is a power cut the guest never learns about. etcd survives that (its
// WAL is fsynced), but a workload's in-flight writes are the exposure.
//
// The talosconfig is the one cluster.Up wrote into this machine's state dir at
// step 4. Reading it from there rather than $TALOSCONFIG is deliberate: the
// credentials that stop a machine must be THAT machine's, and the operator's
// environment may be pointed anywhere.
//
// A machine in MAINTENANCE MODE — created by `apply`, never bootstrapped —
// never gets this rung: it has no talosconfig, so it cannot satisfy the mutual
// TLS that Shutdown requires, and this returns immediately rather than
// dialling. That is safe rather than a compromise — a maintenance node is a
// booted ISO with no applied config and nothing persistent to corrupt.
//
// talosconfig is SECRET. It is never logged and never interpolated into an
// error; see cluster.errSecretParse for why even a parser's own message is
// withheld.
func (h *hvf) shutdownGuest(ctx context.Context, m *unstructured.Unstructured) error {
	// os.ReadFile's error quotes the PATH and never the contents, so it is
	// safe to wrap. Nothing below may relax that.
	talosconfig, err := os.ReadFile(filepath.Join(h.dir(m), "talosconfig"))
	if err != nil {
		return fmt.Errorf("no credentials to ask the guest with (a machine still in "+
			"maintenance mode has none): %w", err)
	}

	endpoint := talosEndpoint(m)

	ctx, cancel := context.WithTimeout(ctx, shutdownRequestTimeout)
	defer cancel()

	c, err := cluster.AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return fmt.Errorf("authenticated Talos client: %w", err)
	}

	defer c.Close() //nolint:errcheck

	// MachineService.Shutdown, exposed on the client — NOT LifecycleService,
	// which carries only Install and Upgrade.
	//
	// It returns once the node has ACCEPTED the request; Talos runs the
	// shutdown sequence after replying. So nil here means "asked", not "gone",
	// and Stop is right to wait on the process afterwards rather than trust it.
	if err := c.Shutdown(ctx); err != nil {
		return fmt.Errorf("asking the Talos API at %s to power the guest off: %w", endpoint, err)
	}

	return nil
}

// halt escalates signals at pid until it is no longer this machine's qemu.
//
// EVERY signal is gated on ProcessMatches, THE FIRST ONE INCLUDED. A pidfile
// that outlived its qemu names a pid the kernel is free to hand to someone
// else — after a reboot, to a low-numbered stranger, plausibly another
// machine's qemu — and an ungated opening SIGTERM would take that process down.
// Gating only the later rungs is not a weaker version of this rule, it is the
// absence of it: the first signal is the one that lands.
//
// The window is not hypothetical even though Observe already verified the pid.
// Stop RE-READS the pidfile rather than reusing what Observe proved, so these
// are two different reads with a graceful-shutdown attempt in between; and the
// most likely outcome of that attempt is an error CAUSED by the guest going
// away (the RPC drops mid-power-off), which logs "graceful shutdown
// unavailable" and arrives here with a pid that has just exited. That is the
// recycled-pid case exactly, reached by the ordinary success path.
//
// Measured against the ungated version: halt(strangerPid, dir) returned nil in
// ~10µs having SIGTERMed a live unrelated process — and reported success,
// because waitGone read the non-match as "gone".
//
// The pid gate is not redundant with it. kill(0, sig) is NOT a no-op: POSIX
// sends the signal to every process in OUR OWN process group. readPid reports 0
// for a pidfile that has gone — which a concurrent destroy causes, since it
// removes the whole state dir — so the pid can become 0 between reads and an
// ungated ladder would SIGTERM and then SIGKILL tinq itself.
//
// The gate is <= 0, not == 0, and the negative half earns its place: readPid
// runs the pidfile through strconv.Atoi, so a corrupt or partially written one
// reading "-1" yields a NEGATIVE pid rather than a parse failure. kill(-1, sig)
// is strictly worse than kill(0, sig) — it signals every process the caller has
// permission to signal, not merely its own process group. ProcessMatches covers
// both cases, but it does not EXPLAIN them, and a future reader deleting the
// comparison as dead code is the failure this paragraph prevents.
//
// A CANCELLED ctx stops the ladder where it stands and returns the error: it
// never escalates, and it never reports success. Both halves are deliberate.
// Escalating would read Ctrl-C as "kill it harder" when it means "stop what you
// are doing" — the operator interrupting a stop did not ask for a power cut, and
// the SIGTERM already sent may yet be honoured. Reporting nil would be worse
// still: the process is very likely alive, and Stop's caller would record a
// machine as stopped that is still running.
//
// The first SIGTERM is NOT gated on ctx. Cancellation cuts the waiting short,
// which is what took ~85s; the signal itself is instant, already gated on
// ProcessMatches, and skipping it would mean an interrupted destroy left a qemu
// running that it had not even asked to exit.
func halt(ctx context.Context, pid int, dir string) error {
	if pid <= 0 || !platform.ProcessMatches(pid, dir) {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	gone, err := waitGone(ctx, pid, dir, sigtermTimeout)
	if err != nil {
		return err
	}
	if gone {
		return nil
	}
	log.Printf("process %d survived SIGTERM after %s; escalating to SIGKILL", pid, sigtermTimeout)
	_ = syscall.Kill(pid, syscall.SIGKILL)

	gone, err = waitGone(ctx, pid, dir, sigtermTimeout)
	if err != nil {
		return err
	}
	if !gone {
		return fmt.Errorf("process %d survived SIGKILL", pid)
	}
	return nil
}

// waitGone polls until the process is no longer OUR qemu, the deadline passes,
// or ctx is cancelled. It re-checks identity rather than mere liveness, so a pid
// recycled mid-wait cannot read as "still running".
//
// The three outcomes are distinct and callers must keep them distinct:
// (true, nil) gone, (false, nil) deadline passed and it is STILL ours — the only
// outcome that may escalate — and (false, err) the wait was ABANDONED, having
// learned nothing. Collapsing the third into either of the others is the bug
// this signature exists to prevent: read as "gone" it reports a success that did
// not happen, read as "still running" it escalates to SIGKILL on a Ctrl-C, and
// Ctrl-C means "stop what you are doing", not "kill it harder".
//
// The poll is a select on ctx.Done(), not time.Sleep, because a sleeping wait is
// an UNINTERRUPTIBLE one. With a bare sleep the whole ladder was deaf to
// cancellation for as long as it ran — up to ~85s per machine (15s shutdown RPC
// + 60s graceful + 5s SIGTERM + 5s SIGKILL) — and driverkit.Run only looks at
// ctx BETWEEN reconcile ticks, never during one, so a Ctrl-C mid-stop was
// ignored for over a minute with no output to say why. Cancellation is now
// observed within one poll interval.
//
// A Ticker rather than a per-iteration Timer: one allocation for a loop that can
// run 600 times across the graceful budget, and nothing to leak on the way out.
//
// Identity is also what gets this right for a ZOMBIE, which kill(pid, 0) calls
// alive: a zombie's command line is empty, so it matches nothing and the wait
// ends at once instead of burning the full deadline and then SIGKILLing a
// corpse. That trade is paid knowingly, and destroy pays it too now that it
// shares this loop: on darwin ProcessMatches forks `ps`, ten times a second
// for as long as the wait runs — up to 51 forks across a full 5s deadline,
// where a plain liveness check was a single syscall.
func waitGone(ctx context.Context, pid int, dir string, d time.Duration) (bool, error) {
	deadline := time.Now().Add(d)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		// Identity first, deadline second, so a zero or already-expired budget
		// still gets exactly one check — the same shape the sleeping loop had,
		// where the post-deadline re-check was that final look.
		if !platform.ProcessMatches(pid, dir) {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			// Named, not generic: the caller has to be able to tell "we gave up
			// waiting" from "it is gone", because the process is very likely
			// still running and a caller that believes it stopped acts on a
			// false premise.
			return false, fmt.Errorf("gave up waiting for process %d to exit: %w", pid, ctx.Err())
		case <-tick.C:
		}
	}
}

// Destroy takes the WHOLE SCC: the process (which sweeps everything inside the
// VM) and the state dir (everything outside it). Idempotent — it is called on
// every delete tick until it succeeds.
//
// Except on hardware, where the SCC holds no machine to take and the state dir
// holds the only credential to one that survives its own registration — see
// forgetBaremetal.
func (h *hvf) Destroy(ctx context.Context, m *unstructured.Unstructured) error {
	if isBaremetal(m) {
		return forgetBaremetal(m, h.dir(m))
	}
	return destroy(ctx, h.dir(m))
}

func readPid(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "qemu.pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// resolveImage turns spec.image into a path to a local artifact.
//
// The claim carries a NEUTRAL PROFILE NAME (talos-nocloud.img), not a path.
// Resolving it to a local artifact is substrate-local configuration and belongs
// to the provider — same argument as GCP's project. An absolute path in the
// claim would be a leak: it cannot travel to GCP or AWS, where the same profile
// resolves to an image URI or an AMI.
//
// It is a function of its own because -up needs the SAME answer create() uses:
// the ISO it boots is the ISO whose volume id pins the installer, and two
// resolutions of one profile name are two answers waiting to disagree.
func (h *hvf) resolveImage(spec map[string]interface{}) (string, error) {
	image, _ := spec["image"].(string)
	if image == "" {
		return "", fmt.Errorf("spec.image is required")
	}
	if !filepath.IsAbs(image) {
		image = filepath.Join(h.imageRoot, image)
	}
	if _, err := os.Stat(image); err != nil {
		return "", fmt.Errorf("resolve profile %q under %s: %w", spec["image"], h.imageRoot, err)
	}
	return image, nil
}

func (h *hvf) create(m *unstructured.Unstructured, dir string) (int, error) {
	spec, _, _ := unstructured.NestedMap(m.Object, "spec")

	// Resolve host facts BEFORE creating any state. Failing here costs nothing;
	// failing after the disk exists leaves residue behind.
	p, err := h.detect()
	if err != nil {
		return 0, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}

	image, err := h.resolveImage(spec)
	if err != nil {
		return 0, err
	}
	// The symptom is NOT "no bootable media": Talos ISOs carry BOTH BOOTX64.EFI
	// and BOOTAA64.EFI (the very property that defeats ESP-based detection — see
	// platform.InspectImageArch), so UEFI does find a bootloader and GRUB is
	// what fails, visibly, on the serial console. Do not "fix" this message back
	// to the intuitive version; the wording below was observed, not guessed.
	// Warn only; detection returning "" must never block a valid image we simply
	// cannot classify.
	if got := platform.InspectImageArch(image); got != "" && got != p.ImageArch {
		log.Printf("warning: image is %s but host is %s\n"+
			"  the VM starts and UEFI loads a bootloader (Talos ships stubs for\n"+
			"  both arches), then GRUB stops at \"Failed to boot both default and\n"+
			"  fallback entries.\" — no kernel runs, so there is no Talos API.\n"+
			"  this is not a hang — it is the wrong image: %s", got, p.ImageArch, image)
	}

	cpu := specCPU(spec)
	mem := toMB(str(spec["memory"], "2Gi"))
	diskPath := filepath.Join(dir, "system.qcow2")
	if err := ensureQcow2(diskPath, str(spec["disk"], "16Gi")); err != nil {
		return 0, err
	}
	// The OPTIONAL second disk, for PVCs. It is created here beside the system
	// disk but WIRED IN BELOW as an append, never woven into the arg literal:
	// a machine with no dataDisk has to emit precisely the argv it emitted
	// before this field existed.
	dataPath := ""
	if size := specDataDisk(spec); size != "" {
		dataPath = filepath.Join(dir, "data.qcow2")
		if err := ensureQcow2(dataPath, size); err != nil {
			return 0, err
		}
	}

	varsPath := filepath.Join(dir, "efivars.fd")
	if err := ensureEFIVars(varsPath, p.FirmwareVars); err != nil {
		return 0, err
	}

	// user-mode networking: unprivileged by construction. hostfwd is how the
	// control plane reaches the Talos API without a bridge.
	netdev := "user,id=n0"
	for _, hf := range nestedSlice(m, "spec", "hostForwards") {
		h, _ := hf.(map[string]interface{})
		hp, gp := toInt(h["hostPort"]), toInt(h["guestPort"])
		if hp <= 0 || gp <= 0 {
			continue
		}
		// PROTOCOL IS PER-FORWARD, and defaults to tcp only.
		//
		// This emitted tcp unconditionally, which silently has no path for any
		// UDP service — QUIC, WebTransport, DNS. The failure is nasty because
		// the TCP half usually works: an HTTP/3 origin serves its page over h2
		// and then the browser's WebTransport dial goes nowhere, which presents
		// as a certificate rejection rather than a missing route.
		//
		// `both` is the common case for an HTTP/3 endpoint (h2 on TCP and H3 on
		// UDP at the same port), so it is spelled once here rather than forcing
		// two entries that must be kept in step.
		// BIND ADDRESS is per-forward and defaults to loopback.
		//
		// Loopback is the safe default: on macOS it is what Local Network
		// Privacy exempts, so a browser on the same machine reaches it without a
		// permission prompt, and nothing is exposed to the network.
		//
		// But loopback is unreachable from ANOTHER DEVICE. A phone, a tablet, a
		// second laptop on the same Wi-Fi cannot see it at all — which is the
		// difference between "runs on my machine" and "runs in a demo". Set
		// hostAddr to 0.0.0.0 (or a specific interface address) to publish it.
		// That is a deliberate, per-port exposure decision, not a global switch.
		addr := str(h["hostAddr"], defaultHostAddr)
		switch strings.ToLower(str(h["protocol"], "tcp")) {
		case "udp":
			netdev += fmt.Sprintf(",hostfwd=udp:%s:%d-:%d", addr, hp, gp)
		case "both", "tcp+udp":
			netdev += fmt.Sprintf(",hostfwd=tcp:%s:%d-:%d", addr, hp, gp)
			netdev += fmt.Sprintf(",hostfwd=udp:%s:%d-:%d", addr, hp, gp)
		default:
			netdev += fmt.Sprintf(",hostfwd=tcp:%s:%d-:%d", addr, hp, gp)
		}
	}

	args := []string{
		"-machine", p.Machine + ",accel=" + p.Accel, "-cpu", p.CPU,
		"-smp", strconv.Itoa(cpu),
		"-m", strconv.Itoa(mem),
		"-drive", "if=pflash,format=raw,readonly=on,file=" + p.FirmwareCode,
		"-drive", "if=pflash,format=raw,file=" + varsPath,
		// BOOT ORDER IS THE WHOLE INSTALL LIFECYCLE, and it has to be explicit.
		//
		// Talos ships a bootable ISO: you boot it, it installs to disk, and from
		// then on the machine must boot the DISK. If the ISO keeps winning, Talos
		// refuses to install-loop — it halts with
		//
		//   "Talos is already installed to disk but booted from another media
		//    and talos.halt_if_installed=1"
		//
		// which is a dead node, forever. The obvious fix (detach the ISO once
		// install finishes) needs the provider to track installed-ness, i.e. new
		// state that can disagree with reality. `bootindex` gets it for free and
		// STATELESSLY: firmware tries the disk first and only falls through to
		// the ISO while the disk is still blank. Install flips the behaviour
		// because the disk becomes bootable, not because anything recorded that
		// it did.
		//
		// Explicit `-device` for BOTH (rather than the `if=virtio` shorthand) is
		// required to carry bootindex, and it also pins guest enumeration: the
		// system disk is vda and the ISO is vdb. Do not depend on that order for
		// the install target anyway — select by SERIAL; qemu arg order deciding
		// a device name is not a contract worth resting on.
		//
		// THE SERIAL IS AN IDENTITY, AND THAT IS THE WHOLE POINT. `serial=`
		// surfaces in the guest as /sys/block/<dev>/serial, which is what
		// Talos's InstallDiskSelector.Serial reads, and it is what the README
		// now hands out. The alternative it used to hand out — matching on
		// size, `size: '> 10GB'` — only works while exactly one disk is large.
		// Add a data disk and it becomes a coin flip between the OS install
		// target and the user's data: measured on a live node, that selector
		// matches BOTH this disk and the dataDisk below. Same failure the
		// /dev/vdX warning above is about, arriving through a different door.
		"-drive", "if=none,id=sys,format=qcow2,file=" + diskPath,
		"-device", "virtio-blk-pci,drive=sys,serial=" + DiskSerialSystem + ",bootindex=0",
		"-drive", "if=none,id=cd,media=cdrom,file=" + image,
		"-device", "virtio-blk-pci,drive=cd,bootindex=1",
		"-netdev", netdev,
		"-device", "virtio-net-pci,netdev=n0",
		// ENTROPY, and it decides whether the bring-up works at all. Talos's
		// /sbin/init blocks until the kernel CRNG is seeded, and a QEMU guest
		// with no rng device has almost nothing to seed it with: no host IRQ
		// jitter worth counting, no hardware source, and an idle VM generates
		// none of its own. Measured on darwin/arm64, `random: crng init done`
		// arrived 35s, 207s, and NEVER (>300s, twice) across five identical
		// boots — so `[5/10] maintenance` failed 3 times in 5 against a
		// five-minute budget, with the guest console frozen at
		// "executing /sbin/init" and nothing to say why.
		//
		// virtio-rng-pci hands the guest the host's /dev/urandom and the wait
		// becomes single-digit seconds. It is the standard fix, and the failure
		// it removes reads like a hang anywhere else — the API never opens, so
		// there is no node to ask.
		"-device", "virtio-rng-pci",
		"-display", "none",
		"-serial", "file:" + filepath.Join(dir, "serial.log"),
		"-pidfile", filepath.Join(dir, "qemu.pid"),
		"-daemonize",
	}

	// APPENDED, not spliced into the literal above, so the no-dataDisk argv is
	// unchanged down to the position of every element.
	//
	// NO bootindex, deliberately. Firmware tries every bootindex it is handed,
	// and this disk must never be a boot candidate: while the system disk is
	// still blank the only thing that may follow it is the install ISO. A
	// bootindex here would insert the PVC disk into that sequence.
	if dataPath != "" {
		args = append(args,
			"-drive", "if=none,id=data,format=qcow2,file="+dataPath,
			"-device", "virtio-blk-pci,drive=data,serial="+DiskSerialData)
	}

	cmd := exec.Command(p.QEMUBinary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("qemu: %v: %s", err, strings.TrimSpace(string(out)))
	}
	b, err := os.ReadFile(filepath.Join(dir, "qemu.pid"))
	if err != nil {
		return 0, fmt.Errorf("pidfile: %w", err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// ensureQcow2 creates a sparse qcow2 at path, and does NOTHING if one is
// already there.
//
// Never recreated, never resized: system.qcow2 holds the installed OS and
// data.qcow2 holds the user's PVCs. create() runs on EVERY reconcile tick where
// Observe reports absent, so a version of this that rewrote the file would wipe
// a machine the moment its qemu process died and the controller tried to bring
// it back — the exact case where the data matters most.
//
// The suffix trim is not cosmetic. Kubernetes quantities are Gi/Mi; qemu-img
// accepts only G/M and rejects the "i" outright with "Invalid image size
// specified!". Both spellings mean the same power-of-two bytes, so dropping the
// "i" is exact, not a rounding.
func ensureQcow2(path, size string) error {
	// Only ENOENT means "create it". EACCES, ENOTDIR or a symlink loop are
	// reported: treating them as "already there" skips creation and then
	// launches QEMU against a file that does not exist.
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	out, err := exec.Command("qemu-img", "create", "-f", "qcow2", path, strings.TrimSuffix(size, "i")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img: %v: %s", err, out)
	}
	return nil
}

// destroy is idempotent — it is called on every delete tick until it succeeds.
func destroy(ctx context.Context, dir string) error {
	// Destroy does NOT ask the guest to shut down, and that is deliberate: the
	// disks are deleted immediately below, so a clean shutdown buys nothing and
	// costs up to a minute. The asymmetry with Stop is the entire point of
	// having both — an unexplained asymmetry reads as an oversight, so this
	// says it out loud.
	//
	// The ladder is halt's, not a second copy of it.
	//
	// This used to be an inline 50 x 100ms loop over a bare kill(pid, 0) — the
	// same 5s semantics halt spells out, written a second time — and the two
	// copies DIVERGED exactly where it hurts: this one signalled whatever the
	// pidfile named, gating nothing. The rule that every signal is gated on
	// ProcessMatches, THE FIRST ONE INCLUDED, is stated on halt now and kept
	// where the signals are, so no caller can route around it and no second
	// copy can drift away from it again.
	if err := halt(ctx, readPid(dir), dir); err != nil {
		// A CANCELLED teardown is the one failure that must NOT sweep. The
		// ladder stopped early, so the qemu is probably still live and still
		// has system.qcow2 open — deleting the state dir out from under it is
		// not a teardown, it is corruption with a running writer. Blocking is
		// safe precisely because this is idempotent: the next delete tick
		// retries, and until then the finalizer holds, which driverkit's
		// reconcile already calls the correct outcome.
		//
		// A cancel arriving between halt's return and this check reads as
		// cancellation for an error that was really "survived SIGKILL". That
		// costs one retry of an idempotent sweep; the reverse mistake costs a
		// disk.
		//
		// An already-gone machine never reaches here: halt's pid/ProcessMatches
		// gate returns nil without waiting, so teardown still needs neither a
		// live hypervisor nor a reachable node.
		if ctx.Err() != nil {
			return fmt.Errorf("teardown of %s abandoned before the process was confirmed "+
				"gone; state left in place rather than swept from under a live qemu: %w", dir, err)
		}
		// Not fatal, and the asymmetry is the point: destroy is called on every
		// delete tick until it succeeds, so a process we could not kill must
		// not stop the sweep. Leaving the disks behind forever is the worse
		// outcome, and the escalation already logged why it got here.
		log.Printf("destroy: %v; removing state anyway", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	// Reap the now-empty <stateRoot>/<site> parent. os.Remove fails harmlessly
	// while siblings remain, so the last machine of a site takes the site dir
	// with it. An empty directory is trivial residue — and trivial residue is
	// how "zero" quietly becomes "nearly zero".
	os.Remove(filepath.Dir(dir))
	return nil
}

// ensureEFIVars makes path a per-machine, writable copy of the firmware's own
// nvram template, VERBATIM. UEFI vars must be per-machine: a shared copy is how
// two VMs end up fighting over boot state.
//
// Verbatim, because the previous version padded to 64 MiB — correct on aarch64
// only by coincidence, since edk2's aarch64 vars template genuinely is 67108864
// bytes. The x86_64 template is 540672 bytes, and padding it makes QEMU refuse
// to start:
//
//	combined size of system firmware exceeds 8388608 bytes
//
// SIZE — not mere absence — IS THE REGENERATION TRIGGER. Any state dir the
// padding version touched still holds that poisoned file, and an absence-only
// check would preserve it forever: re-running would keep failing on exactly the
// bug this replaces.
//
// The heal is NOT universal, and the x86_64 case is the only one that needs it.
// On aarch64 the template is itself 67108864 bytes, so a file the padding
// version wrote MATCHES the template size and is left alone here. That is
// benign: the 8 MiB combined-firmware limit is an x86_64 limit, and a blank
// 64 MiB varstore is what edk2 reformats in-guest on first boot anyway.
//
// It is deliberately NOT regenerated unconditionally. The guest writes its own
// UEFI boot entries here, and discarding them on every re-create would lose real
// state. A size that disagrees with the template is the signal that the file did
// not come from this template and cannot be trusted; a size that agrees is left
// strictly alone.
func ensureEFIVars(path, template string) error {
	tmplSt, err := os.Stat(template)
	if err != nil {
		// Unreachable in practice: Detect resolves FirmwareVars by statting it.
		return fmt.Errorf("stat nvram template %s: %w", template, err)
	}
	if st, err := os.Stat(path); err == nil && st.Size() == tmplSt.Size() {
		return nil
	}
	b, err := os.ReadFile(template)
	if err != nil {
		return fmt.Errorf("read nvram template %s: %w", template, err)
	}
	return os.WriteFile(path, b, 0o644)
}

// ── tiny helpers ────────────────────────────────────────────────────────────

// registryCA resolves the optional CA for a mirror. caFile is a path read at
// generate time — the seed exports /etc/ssl/seed/root_ca.crt — and ca is inline
// PEM. caFile wins if both are set; neither is the common case. Read here, in
// cmd/tinq, so cluster/ stays pure: it receives already-resolved bytes.
func registryCA(e map[string]interface{}) (string, error) {
	if p := str(e["caFile"], ""); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("caFile %q could not be read: %w", p, err)
		}
		return string(b), nil
	}
	return str(e["ca"], ""), nil
}

func str(v interface{}, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// specCPU resolves spec.cpu, defaulting to 2.
//
// sigs.k8s.io/yaml routes through JSON, so a bootstrap file yields float64 here
// and NEVER int64 — a bare .(int64) assertion silently dropped every
// user-specified cpu count back to the default. toInt takes both, which is also
// what the API server (int64) path needs.
//
// It lives out here so the resolution is testable through the real YAML decoder
// without dragging argv construction along.
func specCPU(spec map[string]interface{}) int {
	if v := toInt(spec["cpu"]); v > 0 {
		return v
	}
	return 2
}

// Disk serials are the machine's DISK NAMING CONTRACT, not decoration. QEMU
// passes `serial=` through to the guest as /sys/block/<dev>/serial, and Talos
// reads it back through InstallDiskSelector.Serial — so these two strings are
// what a generated machine config selects on. Changing one renames a disk out
// from under an already-installed node.
const (
	DiskSerialSystem = "talos-system"
	DiskSerialData   = "talos-data"
)

// specDataDisk resolves spec.dataDisk, the OPTIONAL second disk for PVCs.
//
// "" means no second disk, and that is the default on purpose: a machine
// without it must be the machine this tool built before the field existed —
// same qemu args, same devices, same guest.
//
// Same YAML-through-JSON caveat as specCPU, which is why it reads through str
// rather than asserting .(string) at the call site: a non-string value is "not
// set", never a panic.
func specDataDisk(spec map[string]interface{}) string {
	return str(spec["dataDisk"], "")
}

// dataDiskSerial is the serial cluster.Up selects the PVC volume on, or "" when
// this machine has no data disk.
//
// ONE field decides BOTH halves of storage — the UserVolumeConfig in the
// generated machine config and the StorageClass installed into the cluster — so
// they cannot disagree. It reads through specDataDisk, the same resolution
// create() uses to decide whether to make the disk at all: a `dataDisk: 40`
// with the unit left off is "not set" in both places, which is what makes the
// announced skip in step 10 the first visible sign of the typo rather than a
// Pending PVC an hour later.
func dataDiskSerial(spec map[string]interface{}) string {
	if specDataDisk(spec) == "" {
		return ""
	}
	return DiskSerialData
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func toMB(s string) int {
	s = strings.TrimSpace(s)
	mult := 1
	switch {
	case strings.HasSuffix(s, "Gi"), strings.HasSuffix(s, "G"):
		mult = 1024
	case strings.HasSuffix(s, "Mi"), strings.HasSuffix(s, "M"):
		mult = 1
	}
	n := strings.TrimRight(s, "GiMB")
	v, err := strconv.Atoi(n)
	if err != nil || v <= 0 {
		return 2048
	}
	return v * mult
}

func nestedSlice(m *unstructured.Unstructured, f ...string) []interface{} {
	v, _, _ := unstructured.NestedSlice(m.Object, f...)
	return v
}

// configPatches reads spec.configPatches — machinery config patches applied
// LAST, over everything tinq generates, the same shape `talosctl --config-patch`
// takes. Absent or empty is nil: no patch, byte-identical config.
//
// Each entry may be written EITHER as a block-scalar string OR as an inline
// mapping — both are natural YAML and dropping one silently would apply a config
// the operator did not ask for — so a non-string entry is marshalled back to a
// YAML document. What the patch DOES is not validated here; a patch that cannot
// be parsed or applied is refused at generation (cluster.GenerateConfig), on the
// workstation, before any node has booted.
func configPatches(m *unstructured.Unstructured) ([]string, error) {
	var out []string

	for i, raw := range nestedSlice(m, "spec", "configPatches") {
		// A STRING, deliberately — the talosctl/talhelper convention and what the
		// CRD schema allows. A YAML mapping written inline is a mistake worth
		// naming here, not a shape to silently reshape into a patch nobody wrote.
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("spec.configPatches[%d] is not a string: each entry is a "+
				"machine-config patch, written as a YAML block scalar\n\n"+
				"    configPatches:\n      - |\n        machine:\n          network:\n"+
				"            nameservers: [10.0.0.1]\n\n  (%s)", i, m.GetName())
		}

		if s != "" {
			out = append(out, s)
		}
	}

	return out, nil
}
