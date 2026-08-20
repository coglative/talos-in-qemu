package qemu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coglative/talos-in-qemu/cluster"
	"github.com/coglative/talos-in-qemu/driverkit"
	"github.com/coglative/talos-in-qemu/platform"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ── adopt: the baremetal substrate ──────────────────────────────────────────

func baremetalMachine() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "machine.hvf.fleet.io/v1alpha1",
		"kind":       "TalosMachine",
		"metadata":   map[string]interface{}{"name": "bm0", "namespace": "default"},
		"spec": map[string]interface{}{
			"site": "lab", "role": "talos-cp",
			"baremetal": map[string]interface{}{
				"maintenanceEndpoint": "192.168.1.50",
				"systemDiskSerial":    "S1",
			},
		},
	}}
}

func TestIsBaremetalKeysOnTheSpecBlock(t *testing.T) {
	if !isBaremetal(baremetalMachine()) {
		t.Error("a machine with spec.baremetal was not recognised as baremetal")
	}

	qemu := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"image": "talos.iso"},
	}}
	if isBaremetal(qemu) {
		t.Error("a machine with no spec.baremetal was treated as baremetal\n" +
			"  reason: presence of the block IS the discriminator")
	}
}

// isBaremetal decides whether the four DESTRUCTIVE driver methods may run, so
// every way it can be wrong is not symmetric: a VM mistaken for hardware costs
// a refusal, hardware mistaken for a VM costs the only talosconfig that reaches
// a node that can never be adopted again.
//
// The rows that matter are `scalar` and `null`. spec.baremetal is unschematised
// today — the CRD is a later task — so nothing upstream rejects either shape,
// and a discriminator that measures presence by a successful map cast reads
// both as ABSENT. Ask NestedMap instead of NestedFieldNoCopy and those two rows
// go green-as-a-VM: sweepable, destroyable, state dir removable.
func TestIsBaremetalMeasuresPresenceNotShape(t *testing.T) {
	machine := func(spec map[string]interface{}) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"metadata": map[string]interface{}{"name": "bm0"},
			"spec":     spec,
		}}
	}

	for _, tc := range []struct {
		name      string
		spec      map[string]interface{}
		baremetal bool // may the destructive methods run? (false == may run)
		readable  bool // are there fields to read?
	}{
		{"map", map[string]interface{}{"baremetal": map[string]interface{}{
			"maintenanceEndpoint": "192.168.1.50"}}, true, true},
		{"scalar", map[string]interface{}{"baremetal": "yes"}, true, false},
		{"null", map[string]interface{}{"baremetal": nil}, true, false},
		{"empty-map", map[string]interface{}{"baremetal": map[string]interface{}{}}, true, true},
		{"absent", map[string]interface{}{"image": "talos.iso"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := machine(tc.spec)

			if got := isBaremetal(m); got != tc.baremetal {
				t.Errorf("isBaremetal = %v, want %v\n"+
					"  reason: a present-but-malformed block is a manifest typo, not "+
					"consent to sweep a machine on a desk", got, tc.baremetal)
			}

			block, present := specBaremetal(m)
			if present != tc.baremetal {
				t.Errorf("present = %v, want %v", present, tc.baremetal)
			}
			if (block != nil) != tc.readable {
				t.Errorf("block = %#v, want readable=%v\n"+
					"  reason: presence and well-formedness are different questions and "+
					"only presence may decide destructiveness", block, tc.readable)
			}
		})
	}
}

// The other half of the same guard: a present-but-unreadable block must be
// NAMED, not silently treated as a machine with every field missing. adopt is
// the only caller that reads the block, so it is the only one that can say it.
func TestAdoptRefusesAMalformedBaremetalBlock(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"scalar", "  baremetal: yes\n"},
		{"null", "  baremetal:\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "machine.yaml")
			doc := `apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
` + tc.doc
			if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}

			root := t.TempDir()
			d := &hvf{stateRoot: root, imageRoot: t.TempDir()}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := adoptMachine(ctx, d, path)
			if err == nil {
				t.Fatal("adopt accepted a spec.baremetal that carries no fields")
			}
			if ctx.Err() != nil {
				t.Fatalf("adopt dialled on a block it could not read: %v", err)
			}
			// Not the "endpoint is required" a readable-but-empty block earns.
			// That one sends the operator looking for a field in a block that
			// is not a block, which is the wrong hunt.
			if !strings.Contains(err.Error(), "not a block of fields") {
				t.Errorf("the refusal does not say the block is unreadable: %v", err)
			}
			if entries, readErr := os.ReadDir(root); readErr != nil || len(entries) != 0 {
				t.Errorf("a refused adopt left %v under the state root (err %v), want nothing",
					entries, readErr)
			}
		})
	}
}

func TestBaremetalEndpointsUseTalosDefaultPorts(t *testing.T) {
	m := baremetalMachine()

	if got := baremetalTalosEndpoint(m); got != "192.168.1.50:50000" {
		t.Errorf("talos endpoint = %q, want 192.168.1.50:50000\n"+
			"  reason: there is no forward on hardware; apid serves its own default port", got)
	}

	if got := baremetalKubeEndpoint(m); got != "https://192.168.1.50:6443" {
		t.Errorf("kube endpoint = %q, want https://192.168.1.50:6443", got)
	}
}

func TestVMVerbsRefuseABaremetalMachine(t *testing.T) {
	for _, verb := range []string{"apply", "up", "stop", "destroy"} {
		err := refuseWrongSubstrate(baremetalMachine(), verb)
		if err == nil {
			t.Errorf("%s accepted a baremetal machine\n"+
				"  reason: destroy in particular would delete the only talosconfig "+
				"that can reach a node it cannot destroy", verb)
			continue
		}
		if !strings.Contains(err.Error(), "adopt") {
			t.Errorf("%s's refusal does not name the verb that does work: %s", verb, err)
		}
	}
}

func TestAdoptRefusesAQEMUMachine(t *testing.T) {
	qemu := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"image": "talos.iso"},
	}}
	if err := refuseWrongSubstrate(qemu, "adopt"); err == nil {
		t.Error("adopt accepted a machine with no spec.baremetal")
	}
}

// The refusal has to be WIRED IN, not merely written. Every assertion above
// calls refuseWrongSubstrate directly, and all four would stay green with the
// call deleted from standalone — which is the only place a user reaches it.
//
// It also pins the ORDER, and the fixture is what makes that assertable: the
// state root is a regular FILE, so Observe's stat of <root>/<site>/<uid>/
// system.qcow2 fails with ENOTDIR rather than ENOENT and standalone returns
// "observe: ...". Seeing the refusal instead proves nothing observed first —
// which matters because Observe stats a qcow2 and would call a machine that is
// a machine Absent.
func TestStandaloneRefusesABaremetalMachineBeforeObserving(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(root, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
  baremetal:
    maintenanceEndpoint: 192.168.1.50
    systemDiskSerial: S1
`), 0o644); err != nil {
		t.Fatal(err)
	}

	d := &hvf{stateRoot: root, imageRoot: t.TempDir(),
		detect: func() (*platform.Platform, error) {
			t.Error("a refusal must not probe the host: the machine is not this host's guest")
			return nil, fmt.Errorf("no accelerator")
		}}

	for _, verb := range []string{"apply", "up", "stop", "destroy"} {
		t.Run(verb, func(t *testing.T) {
			err := standalone(context.Background(), d, path, verb)
			if err == nil {
				t.Fatalf("standalone %s ran against a baremetal machine", verb)
			}
			// LOAD-BEARING ON hvf.Observe RETURNING AN ERROR FOR ENOTDIR.
			// This assertion can only tell "refused first" from "observed
			// first" because a stat failure that is not ENOENT propagates —
			// see Observe's `return driverkit.Absent, nil, err`. Soften that
			// to Absent for every stat error and standalone stops erroring in
			// Observe at all, so this branch goes vacuous while staying green
			// and the ordering it exists to pin is silently unasserted.
			// Change Observe there and this test needs a new lever.
			if strings.HasPrefix(err.Error(), "observe:") {
				t.Fatalf("standalone %s observed before refusing: %v\n"+
					"  reason: Observe stats system.qcow2 and reports hardware as "+
					"Absent, which is a meaningless answer", verb, err)
			}
			if !strings.Contains(err.Error(), "adopt") {
				t.Errorf("standalone %s's refusal does not name the verb that works: %v", verb, err)
			}
		})
	}
}

// adopt is reachable, spelled the way the docs spell it, and refuses a VM
// through the same door a user opens. A verb missing from AddCommand compiles.
func TestAdoptIsRegisteredAndRefusesAVM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(machineDoc), 0o644); err != nil {
		t.Fatal(err)
	}

	root := RootCmd()
	root.SetArgs([]string{"adopt", "--state-root", t.TempDir(), path})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	err := root.Execute()
	if err == nil {
		t.Fatal("adopt ran against a machine with no spec.baremetal")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("adopt is not registered: %v", err)
	}
	// The REFUSAL, specifically, and not the "endpoint is required" that a
	// machine which got past it fails on next — that one also says
	// "spec.baremetal", so a looser assertion here is green against an adopt
	// that accepted a VM and then tripped over the missing block anyway.
	if !strings.Contains(err.Error(), "`tinq up` is the verb that builds it") {
		t.Errorf("adopt's refusal does not send a VM to the verb that builds it: %v", err)
	}
}

// A PORT IN THE ENDPOINT IS A HANG, and that is why it is refused rather than
// left to fail somewhere. The two ports are Talos's own and adopt appends them,
// so "10.0.0.5:50000" becomes "10.0.0.5:50000:50000" — measured: ten minutes of
// the maintenance budget spent on an address nothing can dial, with only
// "waiting for the Talos maintenance API" printed to explain it.
//
// The refusal must land BEFORE the wait, which is what the deadline asserts:
// this test may not take ten minutes to discover a typo.
func TestAdoptRefusesAnEndpointCarryingAPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
  baremetal:
    maintenanceEndpoint: 10.0.0.5:50000
    systemDiskSerial: S1
`), 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	d := &hvf{stateRoot: root, imageRoot: t.TempDir()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := adoptMachine(ctx, d, path)
	if err == nil {
		t.Fatal("adopt accepted an endpoint with a port in it")
	}
	if ctx.Err() != nil {
		t.Fatalf("adopt dialled before checking the address it was given: %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.0.5:50000") {
		t.Errorf("the refusal does not quote the endpoint it rejected: %v", err)
	}
	// The check sits before MkdirAll, and this is the property that buys.
	// Without it the deadline assertion above is equally green against a
	// refusal that has already carved out a state dir for a machine it just
	// rejected — residue named after a typo, left for the operator to find.
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatalf("state root: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("a refused adopt created %d entries under the state root, want 0", len(entries))
	}
}

// adoptRefusalFromTheFile runs adopt against a manifest that is wrong in a way
// the FILE proves, and asserts three things at once: it refused, it refused
// without dialling (the deadline), and it refused without carving out a state
// directory for a machine it rejected.
//
// The deadline is 5s against a maintenance budget of ten MINUTES, so a check
// that slipped below the dial cannot pass this by being fast.
func adoptRefusalFromTheFile(t *testing.T, baremetal string) error {
	t.Helper()

	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
  baremetal:
`+baremetal), 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	d := &hvf{stateRoot: root, imageRoot: t.TempDir()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := adoptMachine(ctx, d, path)
	if err == nil {
		t.Fatal("adopt accepted a manifest the file alone proves wrong")
	}

	if ctx.Err() != nil {
		t.Fatalf("adopt dialled before reading what it was given: %v", err)
	}

	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatalf("state root: %v", readErr)
	}

	if len(entries) != 0 {
		t.Errorf("a refused adopt created %d entries under the state root, want 0\n"+
			"  reason: residue named after a typo, left for the operator to find", len(entries))
	}

	return err
}

// Machinery ANDs every non-empty field of an InstallDiskSelector, so a config
// carrying a serial AND a wwid demands ONE disk reporting both and selects
// nothing. Talos does not report selecting nothing as an error: it installs
// nowhere and the bring-up hangs.
func TestAdoptRefusesAnInstallTargetNamedTwice(t *testing.T) {
	err := adoptRefusalFromTheFile(t, `    maintenanceEndpoint: 192.168.1.50
    systemDiskSerial: S1
    systemDiskWWID: naa.5000c5001b82df21
`)

	if !strings.Contains(err.Error(), "named twice") {
		t.Errorf("the refusal does not say the install target is named twice: %v", err)
	}
}

// A data disk and an EPHEMERAL cap are two answers to "where do PVCs live".
// Choosing between them silently would repartition a disk the operator cannot
// un-overwrite.
func TestAdoptRefusesTwoPlacesForPVCs(t *testing.T) {
	err := adoptRefusalFromTheFile(t, `    maintenanceEndpoint: 192.168.1.50
    systemDiskSerial: S1
    dataDiskSerial: S2
    ephemeralMaxSize: 120GB
`)

	for _, want := range []string{"TWO places", "dataDiskSerial", "ephemeralMaxSize"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// THE CONTROLLER REACHES Destroy WITH NO SUBSTRATE CHECK IN FRONT OF IT.
// refuseWrongSubstrate guards the CLI verbs only, and driverkit's reconcile
// handles a deletion timestamp before it Observes — so `kubectl delete
// talosmachine bm0`, on the machine the docs tell you to register after adopt,
// lands here directly. Sweeping the state dir there deletes the sole
// talosconfig for a node that left maintenance mode when it was adopted and
// can never be adopted again: the machine survives, the key to it does not.
//
// Both halves matter. The QEMU subtest is the regression guard — this is the
// method the controller calls on every delete tick, and a guard that also
// stops sweeping VMs has traded one leak for another.
func TestDestroyForgetsHardwareAndStillSweepsAVM(t *testing.T) {
	// seed builds a state dir with one file in it and returns both paths.
	seed := func(t *testing.T, h *hvf, m *unstructured.Unstructured, name string) (string, string) {
		t.Helper()
		dir := h.dir(m)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte("not a secret, a fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, f
	}

	t.Run("baremetal", func(t *testing.T) {
		h := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir(),
			detect: func() (*platform.Platform, error) {
				t.Error("forgetting a machine must not probe the host")
				return nil, fmt.Errorf("no accelerator")
			}}
		m := baremetalMachine()
		m.SetUID("bm0-uid")
		dir, cfg := seed(t, h, m, "talosconfig")

		if err := h.Destroy(context.Background(), m); err != nil {
			t.Fatalf("Destroy of a baremetal machine = %v, want nil\n"+
				"  reason: an error here BLOCKS deletion and wedges the finalizer forever", err)
		}
		if _, err := os.Stat(cfg); err != nil {
			t.Fatalf("Destroy deleted %s: %v\n"+
				"  reason: that is the ONLY credential that reaches a node this tool "+
				"cannot destroy and cannot re-adopt", cfg, err)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("Destroy removed the state dir of a machine it does not own: %v", err)
		}
	})

	t.Run("qemu", func(t *testing.T) {
		h := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir()}
		m := &unstructured.Unstructured{Object: map[string]interface{}{
			"metadata": map[string]interface{}{"name": "vm0"},
			"spec":     map[string]interface{}{"site": "lab", "image": "talos.iso"},
		}}
		m.SetUID("vm0-uid")
		dir, _ := seed(t, h, m, "system.qcow2")

		if err := h.Destroy(context.Background(), m); err != nil {
			t.Fatalf("Destroy of a VM = %v, want nil", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("Destroy left the state dir of a VM behind (stat: %v)\n"+
				"  reason: the baremetal guard must not cost the QEMU path its sweep", err)
		}
	})
}

// Observe must not call hardware Absent or Stopped: both are answers about
// system.qcow2, both read as "not up yet", and plan() turns either into a
// Create against a machine on a desk on the very next tick.
func TestObserveDoesNotCallHardwareAbsent(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir()}
	m := baremetalMachine()
	m.SetUID("bm0-uid")

	state, status, err := h.Observe(context.Background(), m)
	if err != nil {
		t.Fatalf("Observe of a baremetal machine = %v, want nil", err)
	}
	if state != driverkit.Running {
		t.Fatalf("Observe reported %v for hardware, want Running\n"+
			"  reason: Absent and Stopped both make plan() ask Create to build a "+
			"machine that already exists", state)
	}
	if got := status["apiEndpoint"]; got != "192.168.1.50:50000" {
		t.Errorf("status apiEndpoint = %v, want the node's own address\n"+
			"  reason: Running here is not a liveness claim, so status has to carry "+
			"the address that can actually answer one", got)
	}
	if _, ok := status["pid"]; ok {
		t.Error("status carries a pid for a process this host never started")
	}
}

// Create and Stop must return nil, not an error. The controller retries a
// failed verb on every tick and this one could never clear — a permanent error
// spin is noise that teaches an operator to stop reading the log.
//
// THE LOG IS THE ONLY LEVER STOP HAS. nil is not evidence Stop refused: delete
// its guard and Stop still returns nil, because Observe's own guard reports
// Running, readPid finds no pidfile and returns 0, shutdownGuest fails on the
// talosconfig that is not there — and that failure is LOGGED, NOT RETURNED —
// and halt(ctx, 0, dir) signals nothing and reports success. The state root is
// no lever either, since none of that writes a file. So the guard is asserted
// by what it says and by what a fall-through would have said instead.
func TestCreateAndStopDoNotSpinOnHardware(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	h := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir(),
		detect: func() (*platform.Platform, error) {
			t.Error("a refusal must not probe the host")
			return nil, fmt.Errorf("no accelerator")
		}}
	m := baremetalMachine()
	m.SetUID("bm0-uid")

	if err := h.Create(context.Background(), m); err != nil {
		t.Errorf("Create on hardware = %v, want nil", err)
	}
	if err := h.Stop(context.Background(), m); err != nil {
		t.Errorf("Stop on hardware = %v, want nil", err)
	}
	if entries, err := os.ReadDir(h.stateRoot); err != nil || len(entries) != 0 {
		t.Errorf("state root holds %v (err %v) after a refusal, want nothing", entries, err)
	}

	out := buf.String()
	if !strings.Contains(out, "refusing to create it") {
		t.Errorf("Create did not announce its refusal:\n%s", out)
	}
	if !strings.Contains(out, "refusing to stop it") {
		t.Errorf("Stop did not announce its refusal — it fell through to the VM path:\n%s\n"+
			"  reason: nil is what a missing guard returns too; this line is the "+
			"difference", out)
	}
	// The fall-through's OWN fingerprint, and the half that catches a guard
	// moved below Observe rather than deleted. Nothing on the hardware path may
	// try to talk to a guest.
	if strings.Contains(out, "graceful shutdown unavailable") {
		t.Errorf("Stop tried to power off a machine on a desk:\n%s\n"+
			"  reason: it dialled a talosconfig that adopt wrote for a node this "+
			"driver has no power control over", out)
	}
}

// staticMachine is baremetalMachine with the block the target hardware needs.
// The maintenance address and the static address are DELIBERATELY EQUAL, which
// is the no-DHCP case: the operator gave the node its final address at the GRUB
// prompt, so nothing moves.
func staticMachine() *unstructured.Unstructured {
	m := baremetalMachine()
	m.Object["spec"].(map[string]interface{})["baremetal"] = map[string]interface{}{
		"maintenanceEndpoint": "192.168.2.10",
		"systemDiskSerial":    "S1",
		"network": map[string]interface{}{
			"address":      "192.168.2.10/24",
			"gateway":      "192.168.2.1",
			"nameservers":  []interface{}{"1.1.1.1"},
			"hardwareAddr": "84:47:09:47:35:f9",
		},
	}

	return m
}

func TestBaremetalNetworkReadsEveryFieldOutOfTheBlock(t *testing.T) {
	n, err := baremetalNetwork(staticMachine())
	if err != nil {
		t.Fatalf("baremetalNetwork: %s", err)
	}

	if n == nil {
		t.Fatal("the network block was not read at all")
	}

	// EVERY field, because a reader that drops one produces a config that
	// installs and then cannot resolve, or route, or come up at all — and each
	// of those looks like a different bug.
	if n.Address != "192.168.2.10/24" || n.Gateway != "192.168.2.1" ||
		n.HardwareAddr != "84:47:09:47:35:f9" ||
		len(n.Nameservers) != 1 || n.Nameservers[0] != "1.1.1.1" {
		t.Errorf("baremetalNetwork = %+v, want every field of the manifest block", n)
	}
}

func TestBaremetalNetworkIsNilForADHCPMachine(t *testing.T) {
	n, err := baremetalNetwork(baremetalMachine())
	if err != nil {
		t.Fatalf("baremetalNetwork: %s", err)
	}

	if n != nil {
		t.Errorf("a machine with no network block produced %+v, want nil — absent is the "+
			"answer every node gave before this field existed", n)
	}
}

func TestBaremetalNetworkRefusesAMalformedBlock(t *testing.T) {
	m := baremetalMachine()
	m.Object["spec"].(map[string]interface{})["baremetal"].(map[string]interface{})["network"] = "192.168.2.10/24"

	if _, err := baremetalNetwork(m); err == nil {
		t.Error("a scalar `network:` was accepted, and every field read off it would be empty")
	}
}

// THE ENDPOINTS A CLIENT KEEPS. Both are baked into artifacts on disk — the
// talosconfig and the kubeconfig — so pointing them at the maintenance address
// leaves the operator with two files that dial an address the node dropped.
func TestBaremetalEndpointsFollowTheStaticAddress(t *testing.T) {
	m := staticMachine()
	m.Object["spec"].(map[string]interface{})["baremetal"].(map[string]interface{})["maintenanceEndpoint"] = "192.168.2.99"

	if got := baremetalTalosEndpoint(m); got != "192.168.2.99:50000" {
		t.Errorf("talos endpoint = %q, want 192.168.2.99:50000 — before the install the node "+
			"holds only the maintenance address", got)
	}

	if got := baremetalInstalledEndpoint(m); got != "192.168.2.10:50000" {
		t.Errorf("installed endpoint = %q, want 192.168.2.10:50000", got)
	}

	if got := baremetalKubeEndpoint(m); got != "https://192.168.2.10:6443" {
		t.Errorf("kube endpoint = %q, want https://192.168.2.10:6443 — a kubeconfig pointing "+
			"at the maintenance address cannot be used after the install reboot", got)
	}
}

func TestBaremetalEndpointsStayPutWithoutANetworkBlock(t *testing.T) {
	m := baremetalMachine()

	if got := baremetalInstalledEndpoint(m); got != "192.168.1.50:50000" {
		t.Errorf("installed endpoint = %q, want 192.168.1.50:50000 — a DHCP node does not move", got)
	}

	if got := baremetalKubeEndpoint(m); got != "https://192.168.1.50:6443" {
		t.Errorf("kube endpoint = %q, want https://192.168.1.50:6443", got)
	}
}

// Observe reports what a client dials, and after the install that is the static
// address. Reporting the maintenance one puts an address in kubectl output that
// stopped answering at the first reboot.
func TestObserveReportsTheAddressTheNodeKeeps(t *testing.T) {
	_, status, err := observeBaremetal(staticMachine(), t.TempDir())
	if err != nil {
		t.Fatalf("observeBaremetal: %s", err)
	}

	if got := status["apiEndpoint"]; got != "192.168.2.10:50000" {
		t.Errorf("status.apiEndpoint = %v, want 192.168.2.10:50000", got)
	}
}

// The refusal must land BEFORE the ten-minute maintenance wait. Reaching it
// afterwards is ten minutes spent on a verdict that was provable from the file.
func TestAdoptRefusesAnUnreachableStaticAddressWithoutDialling(t *testing.T) {
	// The same on-disk shape TestAdoptRefusesAnEndpointCarryingAPort uses
	// (adopt_test.go:285): a machine file in a temp dir and an hvf rooted in
	// another. There is no helper for this in the package; do not invent one.
	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
  baremetal:
    maintenanceEndpoint: 192.168.1.186
    systemDiskSerial: S1
    network:
      address: 192.168.2.10/24
      gateway: 192.168.2.1
      nameservers: [1.1.1.1]
      hardwareAddr: 84:47:09:47:35:f9
`), 0o644); err != nil {
		t.Fatal(err)
	}

	d := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir()}

	started := time.Now()
	err := adoptMachine(context.Background(), d, path)

	if err == nil {
		t.Fatal("adopt accepted a static address on a segment the node is not on")
	}

	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("adopt took %s to refuse, so it dialled first\n"+
			"  reason: this verdict comes from the manifest alone", elapsed)
	}

	if !strings.Contains(err.Error(), "192.168.2.10/24") {
		t.Errorf("the refusal does not name the address that caused it: %s", err)
	}
}

// ── adopt: the ip= line on a maintenance timeout ────────────────────────────

// The NETMASK is the whole reason this is generated rather than documented.
// /24 is the one everybody types correctly; /26 is the one that strands a
// machine, and it is exactly the arithmetic a human does in their head at a
// GRUB prompt with a laptop balanced on a rack rail.
func TestKernelCmdlineHintDerivesTheNetmask(t *testing.T) {
	// The gateway varies in the /16 case so that a hint hard-coding one address
	// cannot pass the whole table: the gateway must come from the file too.
	cases := []struct {
		address string
		gateway string
		want    string
	}{
		{"192.168.2.10/24", "192.168.2.1", "ip=192.168.2.10::192.168.2.1:255.255.255.0::<your-nic>:off"},
		{"192.168.2.10/26", "192.168.2.1", "ip=192.168.2.10::192.168.2.1:255.255.255.192::<your-nic>:off"},
		{"192.168.2.10/16", "192.168.0.1", "ip=192.168.2.10::192.168.0.1:255.255.0.0::<your-nic>:off"},
	}

	for _, c := range cases {
		t.Run(c.address, func(t *testing.T) {
			n := &cluster.Network{Address: c.address, Gateway: c.gateway}

			got := kernelCmdlineHint(errors.New("gave up waiting"), n)
			if !strings.Contains(got.Error(), c.want) {
				t.Errorf("the hint does not carry %q:\n%s", c.want, got)
			}

			// The original failure must survive. A hint that replaces the error
			// hides which wait actually timed out.
			if !strings.Contains(got.Error(), "gave up waiting") {
				t.Errorf("the hint swallowed the failure it decorates:\n%s", got)
			}
		})
	}
}

func TestKernelCmdlineHintLeavesADHCPFailureAlone(t *testing.T) {
	// A node with no static block was reachable by DHCP or it was not, and an
	// ip= recipe is advice for a problem it does not have.
	want := errors.New("gave up waiting")

	if got := kernelCmdlineHint(want, nil); got != want {
		t.Errorf("the failure was decorated for a machine with no network block:\n%s", got)
	}
}

func TestKernelCmdlineHintLeavesAMalformedAddressAlone(t *testing.T) {
	// An address this broken has no prefix to derive a netmask from, so there
	// is no hint to give. A DECORATION MUST NEVER REPLACE THE ERROR IT
	// DECORATES: if this regresses, a maintenance timeout is reported as an
	// address parse failure, and the operator debugs the manifest instead of
	// the node that never answered.
	want := errors.New("gave up waiting")

	if got := kernelCmdlineHint(want, &cluster.Network{Address: "nonsense"}); got != want {
		t.Errorf("a malformed address replaced the failure it was meant to decorate:\n%s", got)
	}
}

// A RE-RUN MUST NOT WAIT FOR MAINTENANCE MODE. Up is idempotent and its own
// failure message says to re-run; a pre-flight that spends ten minutes proving
// the node left maintenance mode forever makes that advice a trap.
//
// The talosconfig here is deliberately garbage: what is asserted is WHICH path
// adopt took, and a fast failure on a credential it cannot parse proves it took
// the authenticated one. A maintenance wait would still be running.
func TestAdoptDoesNotWaitForMaintenanceOnAConfiguredMachine(t *testing.T) {
	d := &hvf{stateRoot: t.TempDir(), imageRoot: t.TempDir()}

	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: bm0, namespace: default}
spec:
  site: lab
  role: talos-cp
  baremetal:
    maintenanceEndpoint: 192.168.1.50
    systemDiskSerial: S1
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// READ THROUGH readMachine, not built by hand. d.dir keys on the UID
	// (main.go:507) and readMachine SYNTHESISES one for a manifest that carries
	// none (main.go:347), so a hand-built machine keys a different directory
	// and seeds a talosconfig adoptMachine never reads — a test that then
	// passes for the wrong reason, or in this case cannot pass at all.
	m, err := readMachine(path)
	if err != nil {
		t.Fatal(err)
	}

	dir := d.dir(m)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "talosconfig"), []byte("not a talosconfig"), 0o600); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	err = adoptMachine(context.Background(), d, path)

	if err == nil {
		t.Fatal("adopt succeeded against a node that does not exist")
	}

	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Errorf("adopt spent %s before failing, so it waited for maintenance mode\n"+
			"  reason: an installed node never serves that API again, and Up's own failure\n"+
			"  message tells the operator to re-run", elapsed)
	}

	if strings.Contains(err.Error(), "maintenance") {
		t.Errorf("adopt failed on the maintenance API for a machine that already has a "+
			"talosconfig:\n%s", err)
	}

	// The three assertions above are all satisfied by ANY fast refusal, and
	// adoptMachine has several of them before it ever reads the talosconfig: the
	// substrate, the malformed block, the missing endpoint, the port, the network
	// check. This one is the credential refusal (cluster.errSecretParse), which
	// only the authenticated branch can raise — without it the test would keep
	// passing after a new early refusal started short-circuiting the very path it
	// exists to pin.
	if !strings.Contains(err.Error(), "the talosconfig could not be parsed") {
		t.Errorf("adopt did not reach the authenticated call; it failed earlier with:\n%s", err)
	}
}
