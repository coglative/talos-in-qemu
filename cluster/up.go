package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"google.golang.org/grpc/codes"
)

// THE OUTPUT IS THE FEATURE. This file is a bring-up sequence, but what it
// exists to produce is a transcript an operator LEARNS TALOS from rather than
// trusts blindly. Every step announces the operation; the four non-obvious ones
// announce the reason, and each of those reasons is a failure this project has
// actually been bitten by:
//
//	install disk by SERIAL — a size matcher is a coin flip once a data disk
//	exists, and losing it installs the OS over the user's PVCs.
//
//	installer pinned to the IMAGE's version — left unset Talos substitutes the
//	config generator's, and a fresh install silently becomes a cross-version
//	upgrade that either gets rejected or hangs at /sbin/init.
//
//	console arg for THE NODE — the installed system writes its own kernel
//	cmdline and inherits nothing from the ISO, so serial goes dead at exactly
//	the boot you need to watch, and the argument is arch-specific.
//
//	bootstrap fired while the node is `booting` — waiting for `running`
//	DEADLOCKS: a control-plane node cannot reach `running` until etcd exists,
//	and bootstrap is what creates etcd.
//
// Bring-up is BOOTSTRAP ONLY, like the rest of this package. It creates a
// cluster; it never upgrades, scales or reconciles one.
//
// It is also IDEMPOTENT, which is a different claim and not in tension with
// that one: run twice it converges on the same cluster instead of building a
// second, because a stopped machine is started again with `up`. Every step that
// can already be done is decided by ASKING the node — which client can complete
// a handshake, whether a bootstrap is refused — never by reading back something
// this tool wrote down.

// Ten steps, and the count is printed in every line. It lives here so the
// transcript cannot claim a total the sequence does not have.
const upSteps = 10

// detailIndent lines continuation text up under the step's own text.
const detailIndent = "                        "

const (
	// maintenanceTimeout covers ISO boot to a serving maintenance API.
	maintenanceTimeout = 5 * time.Minute
	// installTimeout covers install, reboot and the installed system's apid
	// coming back with the cluster PKI. It is the longest wait in a bring-up.
	installTimeout = 10 * time.Minute
	// NodeVersionTimeout bounds asking an installed node what version it is.
	//
	// SHORT, because it is not a wait for a node to become ready — it is a
	// question to one that is supposed to be ready already, and the caller has
	// its own budget for readiness. Long enough to ride out a dropped packet on
	// a wireless uplink, short enough that a node which is genuinely gone is
	// reported as gone rather than sat on.
	NodeVersionTimeout = 30 * time.Second
	// bootstrapTimeout covers the gap between apid serving the cluster PKI and
	// the node being able to accept a bootstrap — containerd starting, and the
	// clock coming into sync. Both are usually seconds; this is generous
	// because the failure it replaces was a bring-up that died outright.
	bootstrapTimeout = 5 * time.Minute
	// kubeconfigTimeout covers the apiserver starting far enough to mint an
	// admin kubeconfig, which is not immediate after bootstrap.
	kubeconfigTimeout = 5 * time.Minute
	// nodeReadyTimeout covers kubelet joining, the CNI landing and the node
	// reporting Ready.
	nodeReadyTimeout = 10 * time.Minute
)

// UpOptions is everything a bring-up depends on that this package cannot know
// for itself.
//
// The serials, the endpoints and the node's own facts all come from package
// main, which owns the qemu invocation. Copying any of them into this package
// would compile, read correctly, and drift the first time main.go changed one.
type UpOptions struct {
	// ClusterName names the cluster and the talosconfig context.
	ClusterName string
	// StateDir is the machine's existing state directory. The four artifacts
	// are written into it so -destroy sweeps them with everything else and the
	// secrets do not outlive the cluster.
	StateDir string
	// TalosEndpoint is the address a client dials to reach this node's apid,
	// host:port. Under QEMU that is the host side of a forward; for an adopted
	// node it is the node's own address, where there is no forward at all. It
	// is also what apid's certificate is issued for — see apiAddress.
	TalosEndpoint string
	// KubeEndpoint is the same address for kube-apiserver, as a URL: a
	// forward's host side under QEMU, the node's own address on hardware.
	KubeEndpoint string
	// SystemDisk names the install target, by serial or by WWID.
	SystemDisk DiskRef
	// DataDiskSerial is the PVC disk's serial, when PVCs get a disk of their
	// own. Empty means they do not.
	DataDiskSerial string
	// EphemeralMaxSize caps EPHEMERAL so the user volume can take the rest of
	// the SYSTEM disk — the single-disk alternative to DataDiskSerial above.
	// See ConfigInput.EphemeralMaxSize for what that does and does not buy.
	//
	// It and DataDiskSerial are two answers to "where do PVCs live", so setting
	// both is refused by the caller that reads them from a manifest, before
	// anything is dialled.
	EphemeralMaxSize string

	// (hasUserVolume below is how the two halves of storage stay in agreement;
	// see its comment.)

	// TalosVersion is the node's Talos version, e.g. "v1.13.7". RESOLVED BY THE
	// CALLER, and that is what lets one sequence serve two substrates: a QEMU
	// bring-up reads it from the ISO's volume id before booting anything, and
	// an adopted node is asked directly because it is already running. Empty is
	// a real state and step 3 refuses it — see errUnknownTalosVersion.
	TalosVersion string
	// VersionSource says WHERE TalosVersion came from, for the transcript only.
	// "talos-v1.13.7-amd64.iso (ISO volume id)", or "the node's maintenance API".
	VersionSource string
	// Substrate is step 1's line, rendered by the caller. This package no
	// longer knows what a hypervisor is, and an accelerator or an emulator
	// binary is meaningless for a machine that is a machine.
	Substrate string
	// ConsoleArg is the console kernel argument for the NODE, or "" for none.
	//
	// It was derived from the HOST's architecture, which is sound only because
	// QEMU makes host arch and guest arch the same by construction. Driving a
	// node from a different machine breaks that identity, and nothing in the
	// type system noticed.
	ConsoleArg string
	// DisableKexec asks the node not to kexec on reboot. It exists for ONE
	// substrate — QEMU on macOS/arm64 — and the caller decides, because whether
	// the workaround applies is a fact about the host, which this package no
	// longer holds.
	DisableKexec bool
	// Network is the node's static addressing, or nil for DHCP.
	//
	// There is NO companion field for the address the node answers on
	// afterwards, and there must not be one: it is derived below. A second
	// field holding it would compile, read correctly, and be settable to an
	// address the node will never hold — which is the defect CheckNetwork
	// exists to refuse, reintroduced one layer down.
	Network *Network
	// Registries are the node's image registry mirrors, or nil for none.
	//
	// It is carried through UNVALIDATED, because there is nothing here to
	// validate against: whether something answers at the endpoint is a fact
	// about the caller's host, and the only honest test of a mirror is a pull.
	// The shape is refused where it is read — cmd/tinq's registryMirrors.
	Registries []RegistryMirror
	// ConfigPatches are machinery config patches applied last, over everything
	// generated — see ConfigInput.ConfigPatches. Carried through unchanged; a
	// patch that does not parse or apply is refused at generation, not here.
	ConfigPatches []string

	// Boot starts the VM, or adopts one already running, and returns its pid.
	// Owned by package main: this package knows nothing about qemu.
	Boot func() (int, error)

	// Out receives the transcript. nil means os.Stdout.
	Out io.Writer

	// hooks are the operations that need a real VM and a real cluster. nil
	// means the real ones. It is UNEXPORTED on purpose: it is a test seam, not
	// an API, and package main has no business substituting a bring-up.
	hooks *upHooks
}

// hasUserVolume reports whether this machine gets a PVC volume at all, by
// EITHER route: a dedicated data disk, or a slice carved out of the system
// disk.
//
// IT IS ONE METHOD BECAUSE STORAGE HAS TWO HALVES that must never disagree —
// step 6 emits the user volume, step 10 installs the StorageClass that provisions
// into it, and a machine with one and not the other has PVCs that hang Pending
// forever with nothing failing to say so. When there was a single field they
// simply read it; with two there has to be one place that decides, and this is
// it. Do not inline the `||`.
func (o UpOptions) hasUserVolume() bool {
	return o.DataDiskSerial != "" || o.EphemeralMaxSize != ""
}

// upHooks is the seam that makes the transcript testable without booting
// anything. Every entry is one round trip to a node or a cluster; nothing that
// merely formats a line is in here, because that is the part under test.
type upHooks struct {
	generateConfig     func(ConfigInput) (*Generated, error)
	waitMaintenance    func(ctx context.Context, endpoint string, timeout time.Duration) error
	applyConfig        func(ctx context.Context, endpoint string, config []byte) error
	waitBootstrapReady func(ctx context.Context, talosconfig []byte, endpoint string, timeout time.Duration) error
	bootstrap          func(ctx context.Context, talosconfig []byte, endpoint string) error
	kubeconfig         func(ctx context.Context, talosconfig []byte, endpoint string) ([]byte, error)
	waitNodeReady      func(ctx context.Context, kubeconfig []byte, timeout time.Duration) error
	installStorage     func(ctx context.Context, kubeconfig []byte) error
}

func realHooks() *upHooks {
	return &upHooks{
		generateConfig:     GenerateConfig,
		waitMaintenance:    WaitMaintenance,
		applyConfig:        applyConfiguration,
		waitBootstrapReady: WaitBootstrapReady,
		bootstrap:          bootstrapEtcd,
		kubeconfig:         fetchKubeconfig,
		waitNodeReady:      WaitNodeReady,
		installStorage:     InstallStorage,
	}
}

// Up turns a maintenance-mode Talos node and a state directory into a working
// single-node Kubernetes cluster, announcing each of ten steps as it goes.
//
// HOW THAT NODE CAME TO BE IN MAINTENANCE MODE IS THE CALLER'S BUSINESS, and
// that is what lets one sequence serve two substrates: Boot starts a VM from an
// ISO for `up`, and returns (0, nil) for `adopt`, whose node was booted by a
// human from a stick. Nothing below this line can tell the two apart.
//
// It is IDEMPOTENT, and that is what makes `tinq stop` followed by `tinq up`
// work — the most natural pair of commands there is, and the one that used to
// spend a five-minute maintenance timeout proving the node had left maintenance
// mode forever. A machine that has already been configured skips steps 5 to 7
// and waits for the AUTHENTICATED API instead; a bootstrap the node refuses
// because etcd already exists is a success. Both questions are put to the node,
// never to a file: see the talosconfig read below and alreadyBootstrapped.
//
// Idempotent is not resumable in every case. A config written to the state dir
// but never accepted by the node leaves the two disagreeing — the file says
// configured, the node is still in maintenance mode — and no wait on this side
// can end. That one is destroy and retry, which the error says.
func Up(ctx context.Context, opts UpOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	hooks := opts.hooks
	if hooks == nil {
		hooks = realHooks()
	}

	// Both endpoints are checked BEFORE anything is created, for the same
	// reason create() resolves host facts first: failing here costs nothing,
	// and failing later costs a VM nobody asked to keep. A missing endpoint is
	// otherwise discovered by a wait spending its entire budget on an address
	// that was never there.
	//
	// Both messages describe what the endpoint IS and prescribe no field to
	// fix it in. There are two origins and they have nothing in common: a VM's
	// endpoint is the host side of a forward, from spec.hostForwards, and an
	// adopted node's is derived from spec.baremetal.maintenanceEndpoint, which
	// the CRD forbids alongside hostForwards. A message naming one of them is
	// wrong for the other half of its readers, and naming hostForwards to an
	// adopt would prescribe the exact field the CRD rejects.
	if opts.TalosEndpoint == "" {
		return errors.New("no Talos API endpoint: this is the address a client dials to reach " +
			"this node's Talos API, as host:port — apid's port 50000 at the machine's own " +
			"address, or the host side of a forward to it")
	}

	if opts.KubeEndpoint == "" {
		return errors.New("no Kubernetes API endpoint: this is the URL a client dials to reach " +
			"this node's kube-apiserver — port 6443 at the machine's own address, or the host " +
			"side of a forward to it; a kubeconfig pointing anywhere else cannot be used from " +
			"this host")
	}

	// Refused here, beside the two above, and for the same reason: it is
	// provable from the options alone. Reaching it after Boot spends a VM and a
	// state dir on a verdict that was free — and on hardware it would spend a
	// node that has already been told to install.
	//
	// CheckNetwork is given the MAINTENANCE address, because that is the one
	// that has to sit inside the static prefix. Handing it the installed
	// address instead would compare a value to itself and pass everything.
	maintenanceAddr, err := apiAddress(opts.TalosEndpoint)
	if err != nil {
		return err
	}

	if err := CheckNetwork(opts.Network, maintenanceAddr); err != nil {
		return err
	}

	installedAddr, installed, err := installedEndpoint(opts.TalosEndpoint, opts.Network)
	if err != nil {
		return err
	}

	// GATED ON THE STATIC BLOCK, and it has to be. With no block this package
	// cannot know where the node's kube-apiserver is reached from: under QEMU
	// KubeEndpoint is the host side of a port forward and is SUPPOSED to name
	// an address the node never holds. Every machine that existed before this
	// feature therefore reaches none of the refusal below.
	//
	// With a block the node's post-install address is known, and then the two
	// cannot be allowed to disagree — see checkKubeEndpoint for what a
	// disagreement costs.
	if opts.Network != nil {
		if err := checkKubeEndpoint(opts.KubeEndpoint, installedAddr); err != nil {
			return err
		}
	}

	p := &printer{w: out}

	// ── 1/10 platform ───────────────────────────────────────────────────────
	//
	// Rendered by the CALLER. This package no longer resolves host facts, and
	// the line differs by substrate: a hypervisor, an accelerator and an
	// emulator binary describe a QEMU guest and describe nothing at all about a
	// machine on a desk.
	p.step("platform", "%s", opts.Substrate)

	// ── 2/10 version ────────────────────────────────────────────────────────
	// Empty is a real state — an unclassifiable ISO and a node that reports no
	// tag both produce it — and it has to be printed as one rather than as an
	// empty version. Step 3 is what refuses it.
	shown := opts.TalosVersion
	if shown == "" {
		shown = "UNKNOWN"
	}

	p.step("version", "%s -> %s", opts.VersionSource, shown)

	// ── 3/10 version guard ──────────────────────────────────────────────────
	//
	// `checked` IS NOT DISCARDED, and that is the whole reason CheckVersion
	// returns it. There are three outcomes and only two of them fit in an
	// error: the guard ran and passed, the guard ran and refused, and — the
	// dangerous one — the guard could not run at all. A pre-release volume id
	// such as TALOS_V1_14_0_ALPHA reads as "" from InspectImageVersion, so the
	// guard is silently disabled for exactly the images most likely to break
	// config generation. `_, err :=` here would re-open that hole with nothing
	// visible to show for it.
	checked, err := CheckVersion(opts.TalosVersion)

	switch {
	case err != nil:
		p.step("version guard", "REFUSED: image %s is newer than machinery %s", opts.TalosVersion, GeneratorVersion())

		return err
	case checked:
		p.step("version guard", "machinery %s >= image %s  ok", GeneratorVersion(), opts.TalosVersion)
	default:
		// REFUSED, not a note, and refused HERE rather than four steps later.
		// GenerateConfig rejects an unidentified image unconditionally —
		// there is no branch of it that accepts an empty version, because the
		// installer tag is written to the node's disk and there is no safe
		// value to write. So this arm is already fatal; continuing merely
		// spends a booted VM, a state dir and the five-minute maintenance
		// budget before saying so. Same rule the refusal arm above obeys:
		// failing here costs nothing, failing after the disk exists leaves
		// residue.
		//
		// The lines still explain WHY the version is unknown, because that is
		// the part the shared refusal cannot know: a pre-release volume id
		// such as TALOS_V1_14_0_ALPHA reads as "" from InspectImageVersion,
		// and it is exactly the image an operator is most likely to be
		// holding when this fires.
		p.step("version guard", "REFUSED: this image's Talos version could not be determined")
		p.detail("!! nothing compared this image against machinery %s, and nothing can:", GeneratorVersion())
		p.detail("!! Talos config generation is BACKWARDS compatible only, and exceeding it does")
		p.detail("!! not fail loudly — it emits a plausible config for a Talos that does not exist.")
		p.detail("!! A pre-release volume id (TALOS_V1_14_0_ALPHA) reads as unknown, which is")
		p.detail("!! precisely the image most likely to break generation.")

		return errUnknownTalosVersion()
	}

	// ── 4/10 boot ───────────────────────────────────────────────────────────
	pid, err := opts.Boot()
	if err != nil {
		return err
	}

	p.step("boot", "pid %d, api %s", pid, opts.TalosEndpoint)

	// Everything from here leaves a VM and a state dir behind when it fails.
	fail := func(err error) error {
		return fmt.Errorf("%w\n\n`tinq up` is idempotent: re-running it is the first thing to try, and it "+
			"resumes from whatever this machine already reached rather than starting over.\n\nThe one failure a "+
			"retry cannot repair is a config written to the state dir but never accepted by the node: the state "+
			"dir then says configured while the node is still in maintenance mode, and the authenticated wait "+
			"can only time out. That one is\n\n  tinq destroy <this file>, then try again", err)
	}

	// ── 5/10 – 7/10: configure, or skip what a previous `up` already did ─────
	//
	// A CREDENTIAL, NOT A STATUS, and that distinction is the whole reason this
	// read does not break the rule Observe obeys — never trust a state file.
	// Nothing here is believed about the node. Nothing CAN be: an authenticated
	// call is impossible without this file, so having it is a precondition of
	// asking, and the claim still comes from whether the node completes the
	// mutual TLS handshake below. A node in maintenance mode cannot complete it
	// (see AuthenticatedClient), so a talosconfig sitting beside a node that
	// never took its config fails the wait rather than being believed.
	//
	// Which is exactly the failure the message above names. Step 6 writes this
	// file BEFORE step 7 applies it — deliberately, so the artifacts that
	// explain a failed apply survive it — so the file can outlive an apply that
	// never landed. Nothing on this side can tell that apart from a machine
	// that was stopped, and asking the node is what the wait is for.
	//
	// SHARED WITH adopt, which gates its whole maintenance pre-flight on the
	// same answer. See ReadTalosconfig for why the two must not each have
	// their own copy of this read.
	talosconfig, configured, err := ReadTalosconfig(opts.StateDir)
	if err != nil {
		return fail(err)
	}

	if configured {
		// Every skipped step is still ANNOUNCED, under its own number. The
		// numbering is what an operator reads the sequence by, so a resumed run
		// that jumped from 4 to 8 would read as a bring-up that lost three
		// steps rather than one that had already passed them — and closing the
		// gap by renumbering would be worse: two different meanings for
		// "[ 5/10]" and nothing to tell them apart.
		p.step("maintenance", "skipped (already configured)")
		p.detail("this machine has a talosconfig, so a previous run applied a config to it. The")
		p.detail("node boots the system it INSTALLED and never re-enters maintenance mode, so")
		p.detail("this wait could only spend its whole %s and then fail", maintenanceTimeout)

		p.step("config", "skipped (reusing the talosconfig in the state dir)")
		p.detail("generating again mints a FRESH secrets bundle, and its CA is not the one this")
		p.detail("node was installed with — the new talosconfig could not authenticate to it,")
		p.detail("and overwriting the old one would take away the only way back in")

		// The SAME wait step 7 ends on, on purpose: what has to be true before
		// bootstrap does not depend on how the node got there. It gets the same
		// budget too — a restarted node has an install's worth of work to skip
		// but the same firmware boot, the same kernel and the same apid to
		// start, and a wait that is generous in the one case is not mean in the
		// other.
		started := time.Now()
		if err := hooks.waitBootstrapReady(ctx, talosconfig, installed, installTimeout); err != nil {
			// THE APPLY THAT NEVER LANDED, which the comment above says this side cannot tell
			// from a stopped machine. Asking the node tells them apart: a node still in
			// MAINTENANCE never took the config, so waiting out installTimeout again -- every
			// time, forever -- is the one outcome that cannot become a cluster.
			//
			// A human running `up` sees the failure and clears the state dir. A controller does
			// not: it retries on a timer, and a venue that lands here is stuck for good. So the
			// config that was already generated is applied, rather than regenerated -- a fresh
			// bundle would mint a CA this node's talosconfig cannot authenticate against.
			if !resumeApply(ctx, hooks, opts, p, talosconfig, installed, installTimeout) {
				return fail(err)
			}
		}

		p.step("apply-config", "skipped (already applied), installed system up after %s", took(started))
		p.detail("the gate is the node's own machine stage, and it is the one a fresh bring-up")
		p.detail("passes here too: after a config is applied the MAINTENANCE boot serves the")
		p.detail("cluster PKI as well, so an authenticated answer alone would prove nothing")
	} else {
		// ── 5/10 maintenance ────────────────────────────────────────────
		// A REAL Talos API call, never a dial: a qemu hostfwd is accepted by
		// the HOST, so a TCP connect succeeds against a guest that never booted.
		started := time.Now()
		if err := hooks.waitMaintenance(ctx, opts.TalosEndpoint, maintenanceTimeout); err != nil {
			return fail(err)
		}

		p.step("maintenance", "reachable after %s", took(started))

		if talosconfig, err = configure(ctx, hooks, opts, p, installedAddr, installed); err != nil {
			return fail(err)
		}
	}

	// ── 8/10 bootstrap ──────────────────────────────────────────────────────
	//
	// ATTEMPTED, NEVER PROBED, and tolerating the refusal is what makes the
	// step idempotent. `up` applies the config, waits out the reboot, and only
	// THEN bootstraps: a machine stopped inside that window comes back with
	// apid serving the cluster PKI — so the wait above succeeds — and with no
	// etcd at all. Skipping bootstrap on the strength of that wait would hang
	// in step 9 forever, against a node that can never report Ready. Asking the
	// node instead, and accepting its refusal, collapses both cases into one
	// path with no extra probe and nothing to keep in step.
	switch err := hooks.bootstrap(ctx, talosconfig, installed); {
	case err == nil:
		p.step("bootstrap", "etcd bootstrapped")
		p.detail("fired while the node is 'booting', NOT 'running' — waiting for 'running'")
		p.detail("deadlocks: a control-plane node cannot reach running until etcd exists,")
		p.detail("and bootstrap is the call that creates etcd")
	case alreadyBootstrapped(err):
		p.step("bootstrap", "already bootstrapped (the node refused a second one)")
		p.detail("Talos rejects a bootstrap once its etcd data directory is not empty, and")
		p.detail("that refusal is the node agreeing etcd exists. It is ASKED rather than")
		p.detail("guessed: a machine stopped between apply-config and bootstrap answers the")
		p.detail("authenticated API with no etcd behind it, and skipping this on that")
		p.detail("evidence waits for a Ready node that can never arrive")
	default:
		return fail(err)
	}

	// ── 9/10 kubeconfig ─────────────────────────────────────────────────────
	started := time.Now()

	kubeconfig, err := hooks.kubeconfig(ctx, talosconfig, installed)
	if err != nil {
		return fail(err)
	}

	if err := writeArtifacts(opts.StateDir, map[string][]byte{"kubeconfig": kubeconfig}); err != nil {
		return fail(err)
	}

	// The KUBERNETES API, not the Talos one: the Talos API answers long before
	// kubelet has joined, so nothing on that side can report this.
	if err := hooks.waitNodeReady(ctx, kubeconfig, nodeReadyTimeout); err != nil {
		return fail(err)
	}

	p.step("kubeconfig", "wrote kubeconfig, node Ready after %s", took(started))

	// ── 10/10 storage ───────────────────────────────────────────────────────
	//
	// RE-RUN on a resumed bring-up rather than skipped, and storage.go's
	// "BOOTSTRAP ONLY" is not in tension with that: InstallStorage is a
	// server-side apply of a pinned manifest, so a second run converges on the
	// same objects instead of failing AlreadyExists. Skipping it would mean a
	// machine stopped between step 9 and step 10 could never get a
	// StorageClass, and the only sign would be a PVC that stays Pending —
	// exactly the failure the announced skip below exists to make visible.
	// Re-applying is one round trip; not applying is a cluster that cannot bind
	// a volume.
	//
	// Gated on the SAME predicate as the user volume in step 6, so the two
	// halves of storage cannot disagree. The skip is ANNOUNCED because the way
	// a data disk goes missing is a typo: `dataDisk: 40` omits the unit,
	// decodes as a number, reads as "not set" and produces no disk and no
	// error. Silence here means the first sign of it is a Pending PVC an hour
	// later.
	if !opts.hasUserVolume() {
		p.step("storage", "skipped (no dataDisk and no ephemeralMaxSize)")
		p.detail("neither a data disk nor an EPHEMERAL cap means no user volume and no")
		p.detail("StorageClass, so a PVC with no storageClassName stays Pending forever.")
		p.detail("If you meant to have one, check the unit: `dataDisk: 40` is not a size and")
		p.detail("reads as unset, `dataDisk: 40Gi` is.")
	} else {
		if err := hooks.installStorage(ctx, kubeconfig); err != nil {
			return fail(err)
		}

		p.step("storage", "local-path-provisioner %s, default StorageClass", LocalPathVersion)
		p.detail("root %s", mountPath)
		p.detail("  Talos's root filesystem is read-only, so upstream's /opt path cannot work")
		p.detail("namespace local-path-storage labelled privileged")
	}

	p.summary(opts.StateDir, opts.hasUserVolume())

	return nil
}

// configure is steps 6 and 7: generate this machine's machine config, write the
// artifacts, apply it, and wait for the installed system to come back. It
// returns the talosconfig, which is the credential every step after it needs.
//
// It is a function of its own for ONE reason: it is exactly the half a machine
// that has already been configured must not repeat. Everything in it is what Up
// ran inline before, in the same order, and its errors are returned bare
// because the caller is what knows they leave a VM behind.
func configure(ctx context.Context, hooks *upHooks, opts UpOptions, p *printer, installedAddr, installed string) ([]byte, error) {
	// ── 6/10 config ─────────────────────────────────────────────────────────
	generated, err := hooks.generateConfig(ConfigInput{
		ClusterName:      opts.ClusterName,
		Endpoint:         opts.KubeEndpoint,
		APIAddress:       installedAddr,
		TalosVersion:     opts.TalosVersion,
		ConsoleArg:       opts.ConsoleArg,
		SystemDisk:       opts.SystemDisk,
		DataDiskSerial:   opts.DataDiskSerial,
		EphemeralMaxSize: opts.EphemeralMaxSize,
		// WHETHER kexec is disabled is the CALLER's decision, and the reason
		// is that it is a fact about the host rather than about the node: the
		// one substrate it applies to is QEMU on macOS/arm64. See
		// UpOptions.DisableKexec and, for the gate itself, cmd/tinq's
		// upOptions.
		DisableKexec: opts.DisableKexec,
		// The address a client dials AFTER the install is derived from this
		// block by the caller, so the certificate above and the address below
		// cannot name two different hosts.
		Network: opts.Network,
		// Dropped here, the node pulls every image from the internet and
		// succeeds at doing it — which is why nothing downstream would notice:
		// the failure is an image that exists ONLY on the mirror, days later,
		// in another repository's deploy.
		Registries:    opts.Registries,
		ConfigPatches: opts.ConfigPatches,
	})
	if err != nil {
		return nil, err
	}

	// Written before the config is applied: if the apply fails, the artifacts
	// that explain WHY are already on disk.
	if err := writeArtifacts(opts.StateDir, map[string][]byte{
		"controlplane.yaml": generated.ControlPlane,
		"talosconfig":       generated.Talosconfig,
		"secrets.yaml":      generated.Secrets,
	}); err != nil {
		return nil, err
	}

	p.step("config", "wrote controlplane.yaml, talosconfig, secrets.yaml")
	// DiskRef.String() names WHICH identity, because on a machine whose install
	// target has no serial this line printed "serial " and nothing else — a
	// transcript claiming the selector is a blank serial, on the one run where
	// the reader most wants to check what is about to be overwritten.
	p.detail("diskSelector: %s", opts.SystemDisk)
	p.detail("  a size matcher is a coin flip once there are two large disks, and losing")
	p.detail("  it installs the OS over your PVCs")
	// opts.TalosVersion is non-empty by construction: step 3 refuses an
	// unidentified image and returns, so this line cannot print
	// "installer: ghcr.io/siderolabs/installer: (pinned to YOUR image)" —
	// a claim about a tag that is not there.
	p.detail("installer: ghcr.io/siderolabs/installer:%s (pinned to YOUR image)", opts.TalosVersion)
	p.detail("  left unset Talos substitutes THIS binary's version, and a fresh install")
	p.detail("  silently becomes a cross-version upgrade")
	// GATED, because "" is a real answer and adopt is the caller that gives it.
	// Ungated this announced a BLANK value and credited it to "this host" — on
	// a machine that is not this host, and with nothing of the sort in the
	// config. THE NODE's console, not the host's: the two are the same only
	// under QEMU, where the guest is a guest of the machine that derived it.
	if opts.ConsoleArg != "" {
		p.detail("extraKernelArgs: %s (the node's serial console)", opts.ConsoleArg)
		p.detail("  the installed system writes its own cmdline and inherits nothing from the")
		p.detail("  ISO, so serial goes dead at exactly the boot you need to watch")
	}

	if opts.DisableKexec {
		p.detail("sysctls: kernel.kexec_load_disabled=1")
		p.detail("  Talos kexecs into the kernel it just installed instead of rebooting through")
		p.detail("  firmware. Under QEMU on macOS that path dies in the guest on arm64 and the")
		p.detail("  node never boots what it installed. Applied in MAINTENANCE mode, so it")
		p.detail("  reaches the ISO's running kernel before the reboot it has to change.")
	}

	if opts.Network != nil {
		p.detail("network: %s via %s on %s, dhcp off", opts.Network.Address,
			opts.Network.Gateway, opts.Network.HardwareAddr)
		p.detail("  the installed system writes its own cmdline and inherits nothing from the")
		p.detail("  ISO, so an address that is not in this config is gone at the install reboot")

		// PRINTED ONLY WHEN IT IS TRUE. On a segment with no DHCP the operator
		// gave the node its final address at the GRUB prompt and nothing moves;
		// saying it moved would be a claim about an address change that is not
		// happening.
		if installed != opts.TalosEndpoint {
			p.detail("  this node MOVES: adopted at %s, answers at %s from the reboot onward",
				opts.TalosEndpoint, installed)
		}
	}

	// TWO ARMS, TWO CLAIMS, and they are not the same claim. The second one is
	// weaker on purpose: sharing a disk contains a runaway PVC at a partition
	// boundary but shares the device, so promising what the dedicated-disk arm
	// promises would be a transcript telling the reader they have isolation
	// they do not have.
	switch {
	case opts.DataDiskSerial != "":
		p.detail("userVolume: %s on serial %s", userVolumeName, opts.DataDiskSerial)
		p.detail("  PVCs get their own disk, so a runaway one cannot wedge etcd on EPHEMERAL")

	case opts.EphemeralMaxSize != "":
		p.detail("EPHEMERAL: capped at %s on the system disk", opts.EphemeralMaxSize)
		p.detail("userVolume: %s on the REST of that same disk", userVolumeName)
		p.detail("  one disk, two partitions: a runaway PVC fills its own and cannot ENOSPC")
		p.detail("  etcd — but it shares the device, so this buys no I/O isolation and no")
		p.detail("  survival if the disk dies. A second disk buys all three.")
		p.detail("  SIZES ARE FIXED AT INSTALL: changing them later means a wipe and reinstall")
	}

	// ── 7/10 apply-config ───────────────────────────────────────────────────
	started := time.Now()
	if err := hooks.applyConfig(ctx, opts.TalosEndpoint, generated.ControlPlane); err != nil {
		return nil, err
	}

	// The gate is the node's own STAGE, not merely an authenticated call
	// completing — see WaitBootstrapReady's Trap 4. The config has just been
	// handed to a node that is still in its maintenance boot, and that node
	// starts serving the cluster PKI long before it reboots into what it is
	// installing.
	if err := hooks.waitBootstrapReady(ctx, generated.Talosconfig, installed, installTimeout); err != nil {
		return nil, err
	}

	p.step("apply-config", "installing... rebooting... installed system up after %s", took(started))

	return generated.Talosconfig, nil
}

// printer owns every line of the transcript and, with it, the step numbering.
//
// The number is COUNTED rather than written at each call site: a hand-numbered
// sequence lets a step be inserted, removed or reordered while the transcript
// keeps claiming the old order, which is precisely the lie an operator would
// then debug against.
type printer struct {
	w io.Writer
	n int
}

func (p *printer) step(label, format string, a ...any) {
	p.n++

	fmt.Fprintf(p.w, "[%2d/%d] %-13s %s\n", p.n, upSteps, label, fmt.Sprintf(format, a...))
}

func (p *printer) detail(format string, a ...any) {
	fmt.Fprintf(p.w, "%s%s\n", detailIndent, fmt.Sprintf(format, a...))
}

func (p *printer) line(format string, a ...any) {
	fmt.Fprintf(p.w, format+"\n", a...)
}

// summary prints the two export lines the operator needs and the three
// hardened defaults a freshly bootstrapped Talos cluster has that `kind` does
// not. Each of the three is a deliberate decision, and each is the kind of
// thing that otherwise presents as "Kubernetes is broken".
func (p *printer) summary(stateDir string, storage bool) {
	p.line("")
	p.line("  export TALOSCONFIG=%s", filepath.Join(stateDir, "talosconfig"))
	p.line("  export KUBECONFIG=%s", filepath.Join(stateDir, "kubeconfig"))
	p.line("  kubectl get nodes")
	p.line("")
	p.line("notes — three defaults that differ from a kind cluster, each decided deliberately:")
	p.line("")
	p.line("  control-plane taint  REMOVED (allowSchedulingOnControlPlanes: true). Not a security")
	p.line("                       weakening but a topology correction: in production there would")
	p.line("                       be worker nodes, and on a single node the taint means nothing")
	p.line("                       can ever schedule.")
	p.line("")
	p.line("  PodSecurity          STILL ENFORCED at baseline, which is what a real cluster does")
	p.line("                       and what kind does not. A workload needing more is rejected")
	p.line("                       until you say so per namespace:")
	p.line("                         kubectl label namespace <ns> \\")
	p.line("                           pod-security.kubernetes.io/enforce=privileged")
	p.line("")

	if storage {
		p.line("  storage              local-path-provisioner %s is the default StorageClass, so a", LocalPathVersion)
		p.line("                       PVC with no storageClassName binds. Its data lives on the")
		p.line("                       data disk inside this VM and does not survive `tinq destroy`.")
	} else {
		p.line("  storage              no StorageClass is installed, because spec.dataDisk is not")
		p.line("                       set. A PVC with no storageClassName stays Pending. Set")
		p.line("                       spec.dataDisk (with a unit), then `tinq destroy` and `tinq up`")
		p.line("                       again — and note that PVC data does not survive either way.")
	}

	p.line("")
}

// took reports how long a step ran, rounded to the second. A bring-up's waits
// are measured in tens of seconds against an installing node; sub-second
// precision here would be noise in the one place the transcript is read.
func took(started time.Time) time.Duration { return time.Since(started).Round(time.Second) }

// apiAddress is the host part of a host:port endpoint.
//
// This is the ONE place the certificate's subject alt name is decided, and it
// is decided BY the endpoint rather than beside it: apid's cert has to name
// whatever a client dials, and TalosEndpoint is what a client dials. A second
// configurable field would compile, read correctly, and be settable to
// something the client never contacts — which surfaces as a TLS failure on
// every authenticated call, minutes into a bring-up.
func apiAddress(endpoint string) (string, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("the Talos endpoint %q is not host:port: %w", endpoint, err)
	}

	if host == "" {
		return "", fmt.Errorf("the Talos endpoint %q has no host part, so apid's certificate "+
			"would name nothing", endpoint)
	}

	return host, nil
}

// installedEndpoint is where the node answers AFTER the install reboot, as both
// a bare address — for apid's certificate and the talosconfig — and a dialable
// host:port.
//
// With no static block the node does not move, and both are the maintenance
// endpoint it already answers on. With one, the host changes and the PORT DOES
// NOT: apid serves 50000 before and after the install, so reusing the caller's
// port is not a shortcut, it is the fact.
func installedEndpoint(endpoint string, n *Network) (addr, hostPort string, err error) {
	if addr, err = apiAddress(endpoint); err != nil {
		return "", "", err
	}

	if n == nil {
		return addr, endpoint, nil
	}

	if addr, err = n.IP(); err != nil {
		return "", "", err
	}

	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("the Talos endpoint %q is not host:port: %w", endpoint, err)
	}

	return addr, net.JoinHostPort(addr, port), nil
}

// checkKubeEndpoint refuses a Kubernetes API endpoint whose host is not the
// address the node answers on after the install.
//
// KubeEndpoint CANNOT BE DERIVED the way the Talos one is, which is why it
// survives as a field: under QEMU it is the host side of a forward, and there
// is nothing on this side that could compute one. What it can be is REFUSED,
// once a static block makes the node's post-install address known — the same
// defect the missing InstalledEndpoint field exists to avoid, caught rather
// than made unrepresentable.
//
// And it is worth refusing because this URL is baked into two artifacts at
// generation time: the kubeconfig's server, and cluster.controlPlane.endpoint
// in the machine config the node installs from. Naming an address the node
// never takes produces a node that installs, boots, and brings up a control
// plane pointed at a host nobody answers on — with no way back, because
// regenerating needs the maintenance API and an installed node never serves it
// again.
func checkKubeEndpoint(endpoint, installedAddr string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("the Kubernetes API endpoint %q is not a URL with a host\n\n"+
			"  it is written into the kubeconfig's server verbatim, so it has to be dialable "+
			"as it\n  stands — e.g. https://%s:6443", endpoint, installedAddr)
	}

	if u.Hostname() == installedAddr {
		return nil
	}

	fixed := *u
	fixed.Host = installedAddr

	if port := u.Port(); port != "" {
		fixed.Host = net.JoinHostPort(installedAddr, port)
	}

	return fmt.Errorf("the Kubernetes API endpoint %s names %s, but this node answers at %s\n  "+
		"from the install reboot onward\n\n  that host goes into the kubeconfig's server AND into "+
		"cluster.controlPlane.endpoint in\n  the machine config, both baked at generation time. The "+
		"node would install, boot and\n  serve a control plane at an address neither file names, and "+
		"neither file can be\n  repaired afterwards: regenerating needs the maintenance API, and an "+
		"installed node\n  never serves it again.\n\n  With spec.baremetal.network.address set to %s, "+
		"this endpoint is %s",
		endpoint, u.Hostname(), installedAddr, installedAddr, fixed.String())
}

// ReadTalosconfig reads a machine's talosconfig out of its state directory and
// reports whether there was one.
//
// A CREDENTIAL, NOT A STATUS, and ONE function because both readers depend on
// the same reading of it. Nothing about the node is believed on the strength of
// this file: an authenticated call is impossible without it, so having it is a
// precondition of ASKING, and the claim still comes from whether the node
// completes the handshake — which a node in maintenance mode cannot.
//
// Up gates steps 5 to 7 on the answer; adopt gates its entire maintenance
// pre-flight on it. Two copies of this read would compile and agree on the day
// they were written, and the day they stopped agreeing the symptom would be
// adopt spending its full ten-minute budget on an API an installed node never
// serves again, with nothing in the output pointing at the cause.
//
// A missing file is (nil, false, nil): never configured is an ANSWER, not a
// failure. Anything else is returned, wrapped with the operation and never the
// contents — os.ReadFile's own error quotes the PATH only, which is what makes
// it safe to wrap at all.
func ReadTalosconfig(stateDir string) (talosconfig []byte, configured bool, err error) {
	talosconfig, err = os.ReadFile(filepath.Join(stateDir, "talosconfig"))

	switch {
	case err == nil:
		return talosconfig, true, nil
	case os.IsNotExist(err):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("reading this machine's talosconfig: %w", err)
	}
}

// writeArtifacts writes generated material into the machine's state directory
// at 0600.
//
// Each file is REMOVED FIRST, and that is what makes the mode reliable.
// os.WriteFile's perm argument applies only when it creates the file, so an
// artifact already sitting there at 0644 — from an earlier build, or anything
// else — would keep its mode and leave a private key world-readable with
// nothing reporting it. Chmod'ing afterwards closes that but opens a window
// where the key is on disk readable by everyone; removing first has neither
// problem and needs no second syscall to be correct.
func writeArtifacts(dir string, artifacts map[string][]byte) error {
	for name, data := range artifacts {
		path := filepath.Join(dir, name)

		// The failure is deliberately NOT inspected: everything that can stop
		// this remove — EACCES on the directory, a non-empty directory in the
		// way — stops the write below too, and reports itself there with the
		// operation the caller actually cares about. A branch here would be a
		// guard no test can reach without the write reaching it first.
		_ = os.Remove(path)

		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	return nil
}

// applyConfiguration sends the machine config to a node in MAINTENANCE mode.
//
// Mode REBOOT states what maintenance mode does anyway — it installs and comes
// back as the installed system — rather than leaving it to AUTO, whose answer
// depends on what the node decides the config changed.
//
// The config is SECRET (five certificate authorities and the machine token) and
// is never logged; the node's own error is about fields and endpoints and is
// wrapped normally.
func applyConfiguration(ctx context.Context, endpoint string, config []byte) error {
	c, err := MaintenanceClient(ctx, endpoint)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	if _, err := c.ApplyConfiguration(ctx, &machineapi.ApplyConfigurationRequest{
		Data: config,
		Mode: machineapi.ApplyConfigurationRequest_REBOOT,
	}); err != nil {
		return fmt.Errorf("applying the machine config: %w", err)
	}

	return nil
}

// alreadyBootstrapped reports whether a bootstrap was refused because this
// node's etcd already exists.
//
// THE gRPC CODE IS THE MATCHER, NOT THE MESSAGE. Talos refuses a second
// bootstrap in exactly one place, and it is the only AlreadyExists the
// Bootstrap RPC can return — v1.13.7,
// internal/app/machined/internal/server/v1alpha1/v1alpha1_server.go:457:
//
//	if entries, _ := os.ReadDir(constants.EtcdDataPath); len(entries) > 0 {
//		return nil, status.Error(codes.AlreadyExists, "etcd data directory is not empty")
//	}
//
// The code is part of the API contract and the sentence is not, so matching on
// the sentence is a bring-up that breaks on an upstream rewording — and breaks
// by SWALLOWING a real failure or by failing a healthy cluster, neither of
// which the transcript could explain.
//
// client.StatusCode rather than grpc's own status.Code because it UNWRAPS:
// the error arrives through bootstrapEtcd's %w, and machinery wraps multi-node
// replies in a multierror that status.Code reads as Unknown.
func alreadyBootstrapped(err error) bool {
	return err != nil && client.StatusCode(err) == codes.AlreadyExists
}

// bootstrapEtcd issues the one call that creates the cluster's etcd.
//
// It is fired while the node is still `booting`; see WaitBootstrapReady for why
// waiting for `running` first is a deadlock rather than a slow path.
//
// talosconfig is SECRET and never reaches a log or an error.
func bootstrapEtcd(ctx context.Context, talosconfig []byte, endpoint string) error {
	c, err := AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	return bootstrapWithRetry(ctx, bootstrapTimeout, func(ctx context.Context) error {
		return c.Bootstrap(ctx, &machineapi.BootstrapRequest{})
	})
}

// bootstrapWithRetry issues call until the node stops saying "not yet".
//
// THE FIRST BOOTSTRAP ON REAL HARDWARE ROUTINELY LANDS TOO EARLY, and that is
// what this exists for. Step 7's gate is an authenticated API call, and apid
// serves the cluster PKI as soon as the config is on disk — before containerd
// has finished starting. Talos then refuses with FailedPrecondition, because
// Bootstrap checks IsBootstrapAllowed() (v1.13.7,
// v1alpha1_server.go:442), which v1alpha1_runtime.go:248 documents as "checks
// for CRI to be up". A SECOND transient refusal shares the code and the shape,
// four lines further down: "time is not in sync yet".
//
// Measured: an adopt of a baremetal node passed the authenticated gate after 2s
// and died here; re-running it bootstrapped immediately. Both refusals clear on
// their own, so the only thing the old single-shot call proved was that the
// gate above cannot see far enough — and NOTHING can make it see far enough,
// because the two conditions are about services this side never observes.
//
// ONLY FailedPrecondition IS RETRIED. AlreadyExists is the caller's success
// signal (see alreadyBootstrapped) and cannot clear, so retrying it would turn
// a healthy re-run into a full-budget hang ending in a timeout. Everything else
// is a real failure that waiting cannot improve.
func bootstrapWithRetry(ctx context.Context, timeout time.Duration, call func(context.Context) error) error {
	return waitFor(ctx, timeout, "the node to accept a bootstrap", func(ctx context.Context) error {
		err := call(ctx)

		switch {
		case err == nil:
			return nil

		// NOT YET: keep asking until the budget runs out.
		//
		// Unavailable is here as DEFENSE IN DEPTH rather than because this
		// layer should need it. It is what apid going down for the install
		// reboot looks like — `connection refused` — and with the stage gate in
		// WaitBootstrapReady doing its job the reboot is already over by now.
		// It was NOT already over when that gate merely checked whether an
		// authenticated call succeeded, and a bring-up died here for it. One
		// bounded retry loop is a cheaper insurance policy than trusting that
		// the gate above can never regress.
		case client.StatusCode(err) == codes.FailedPrecondition,
			client.StatusCode(err) == codes.Unavailable:
			return fmt.Errorf("bootstrapping etcd: %w", err)

		// NOT EVER: hand it straight back, wrapped exactly as this function
		// has always wrapped it, so alreadyBootstrapped still reads the code.
		default:
			return stopWaiting{fmt.Errorf("bootstrapping etcd: %w", err)}
		}
	})
}

// fetchKubeconfig asks the node for an admin kubeconfig.
//
// It RETRIES, through the same waitFor every other probe in this package uses.
// The Talos API answers immediately after bootstrap while the apiserver behind
// this call does not, so a single attempt fails on timing alone — and a
// bring-up that dies one step from the end because it asked half a second early
// is the least defensible failure in the sequence.
//
// Both the talosconfig and the answer are SECRET; neither is logged.
func fetchKubeconfig(ctx context.Context, talosconfig []byte, endpoint string) ([]byte, error) {
	c, err := AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return nil, err
	}

	defer c.Close() //nolint:errcheck

	var kubeconfig []byte

	if err := waitFor(ctx, kubeconfigTimeout, "an admin kubeconfig from "+endpoint,
		func(ctx context.Context) error {
			var err error
			kubeconfig, err = c.Kubeconfig(ctx)

			return err
		}); err != nil {
		return nil, err
	}

	return kubeconfig, nil
}

// resumeProbeTimeout is how long resumeApply waits to hear maintenance mode.
//
// SHORT, because it is a question and not a wait: the node has been running long enough to fail the
// install wait above, so it is either in maintenance now or it is not. A generous budget here would
// add itself to every genuinely-failed bring-up.
const resumeProbeTimeout = 15 * time.Second

// resumeApply re-applies an already-generated config to a node still in maintenance mode.
//
// It reports whether the bring-up may continue. False means "not this failure" -- the node is not
// in maintenance, so whatever went wrong is not an apply that was written and never sent, and the
// caller's original error is the honest one to return.
//
// The config is read from the state dir, never regenerated: generating again mints a fresh secrets
// bundle whose CA is not the one the talosconfig beside it carries, so the node would become
// unreachable with the only credential that could reach it.
func resumeApply(ctx context.Context, hooks *upHooks, opts UpOptions, p *printer,
	talosconfig []byte, installed string, installTimeout time.Duration) bool {
	if err := hooks.waitMaintenance(ctx, opts.TalosEndpoint, resumeProbeTimeout); err != nil {
		return false
	}

	config, err := os.ReadFile(filepath.Join(opts.StateDir, "controlplane.yaml"))
	if err != nil {
		return false
	}

	p.step("apply-config", "resuming: the config was written but never applied")
	p.detail("this node has a talosconfig and is STILL IN MAINTENANCE, so a previous run wrote")
	p.detail("its artifacts and stopped before the node took them. Applying what is already")
	p.detail("there, because regenerating would mint a CA that talosconfig cannot authenticate")

	if err := hooks.applyConfig(ctx, opts.TalosEndpoint, config); err != nil {
		return false
	}
	return hooks.waitBootstrapReady(ctx, talosconfig, installed, installTimeout) == nil
}
