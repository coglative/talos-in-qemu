package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// THE OUTPUT IS THE FEATURE, so the output is what this file tests.
//
// Almost every step of a bring-up needs a booted VM, and none of the printing
// does. Up therefore takes its VM-facing operations as hooks (upHooks) and its
// destination as an io.Writer, which is what lets the whole ten-step transcript
// — including the two notes that exist to make silent failures visible — be
// asserted here with nothing running.
//
// The same secret rule as config_test.go applies: nothing derived from
// generated material reaches t.Errorf/t.Fatalf except through redact(). The
// fakes below deliberately carry SECRET-SHAPED markers so
// TestUpNeverPrintsSecrets can prove Up does not interpolate any of them.

// The markers are what a leak would look like. They are base64-shaped and long
// enough that redact() covers them too, so even a failure dump of the
// transcript cannot publish them.
// imageTalosVersion is the version the fake ISO reports, and it is
// DELIBERATELY NOT the generator's.
//
// The installer tag is pinned to the IMAGE, and the whole failure that pin
// exists to prevent is Talos substituting the generator's version instead. A
// fixture where the two agree cannot tell the two apart: `TalosVersion:
// GeneratorVersion()` in the wiring produces a byte-identical transcript and
// survives the entire suite. It is older, not newer, so the version guard still
// passes — an older image is exactly what the guard is designed to admit.
const imageTalosVersion = "v1.12.3"

const (
	fakeControlPlane = "controlplane-secret-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fakeTalosconfig  = "talosconfig-secret-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fakeSecrets      = "secretsbundle-secret-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	fakeKubeconfig   = "kubeconfig-secret-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	// The talosconfig a PREVIOUS `up` left in the state dir. It is deliberately
	// a different string from fakeTalosconfig, which is what THIS run's config
	// generation would produce: a resumed bring-up that quietly generated fresh
	// material and used that instead would be invisible if the two agreed, and
	// what it produces is a new CA the installed node does not trust.
	existingTalosconfig = "existing-talosconfig-secret-EEEEEEEEEEEEEEEEEEEEEEEEEEEE"
)

// recorder captures what Up asked its hooks to do, so a test can assert on
// "storage was never installed" as well as on what got printed.
type recorder struct {
	generateErr error
	failAt      string
	err         error

	called []string
	input  ConfigInput
	// payload is the secret artifact each operation was handed. All four are
	// []byte and every hook takes one, so a swap COMPILES — and applying the
	// talosconfig to a node in maintenance mode, or installing storage with
	// the machine config, fails on the node rather than here.
	payload map[string][]byte
	// endpoint is the address each operation was pointed at. A node with a
	// static block ANSWERS AT TWO ADDRESSES over its life, and every hook below
	// takes a string — so pointing bootstrap at the maintenance address still
	// COMPILES, and fails minutes later against a node that stopped holding it.
	endpoint map[string]string
}

func (r *recorder) call(name string, payload ...[]byte) error {
	r.called = append(r.called, name)

	if len(payload) == 1 {
		if r.payload == nil {
			r.payload = map[string][]byte{}
		}

		r.payload[name] = payload[0]
	}

	if r.failAt == name {
		if r.err != nil {
			return r.err
		}

		return fmt.Errorf("%s failed", name)
	}

	return nil
}

func (r *recorder) at(name, endpoint string, payload ...[]byte) error {
	if r.endpoint == nil {
		r.endpoint = map[string]string{}
	}

	r.endpoint[name] = endpoint

	return r.call(name, payload...)
}

func (r *recorder) did(name string) bool {
	for _, c := range r.called {
		if c == name {
			return true
		}
	}

	return false
}

func (r *recorder) hooks() *upHooks {
	return &upHooks{
		generateConfig: func(in ConfigInput) (*Generated, error) {
			r.input = in

			// The fake must not accept input the REAL GenerateConfig rejects.
			// A fake more permissive than the thing it stands in for is how
			// "-up boots a VM for an image it has already proven it cannot
			// configure" survived this suite: the whole ten-step transcript
			// ran to success with TalosVersion "", a value GenerateConfig has
			// no branch that accepts. The precondition is the real error
			// function, so the two cannot drift.
			if in.TalosVersion == "" {
				return nil, errUnknownTalosVersion()
			}

			if err := r.call("generateConfig"); err != nil {
				return nil, err
			}

			if r.generateErr != nil {
				return nil, r.generateErr
			}

			return &Generated{
				ControlPlane: []byte(fakeControlPlane),
				Talosconfig:  []byte(fakeTalosconfig),
				Secrets:      []byte(fakeSecrets),
			}, nil
		},
		waitMaintenance: func(_ context.Context, endpoint string, _ time.Duration) error {
			return r.at("waitMaintenance", endpoint)
		},
		applyConfig: func(_ context.Context, endpoint string, config []byte) error {
			return r.at("applyConfig", endpoint, config)
		},
		waitBootstrapReady: func(_ context.Context, talosconfig []byte, endpoint string, _ time.Duration) error {
			return r.at("waitBootstrapReady", endpoint, talosconfig)
		},
		bootstrap: func(_ context.Context, talosconfig []byte, endpoint string) error {
			return r.at("bootstrap", endpoint, talosconfig)
		},
		kubeconfig: func(_ context.Context, talosconfig []byte, endpoint string) ([]byte, error) {
			if err := r.at("kubeconfig", endpoint, talosconfig); err != nil {
				return nil, err
			}

			return []byte(fakeKubeconfig), nil
		},
		waitNodeReady: func(_ context.Context, kubeconfig []byte, _ time.Duration) error {
			return r.call("waitNodeReady", kubeconfig)
		},
		waitNodeReadyAt: func(_ context.Context, kubeconfig []byte, addr string, _ time.Duration) error {
			return r.at("waitNodeReadyAt", addr, kubeconfig)
		},
		installStorage: func(_ context.Context, kubeconfig []byte) error {
			return r.call("installStorage", kubeconfig)
		},
	}
}

// The three fixture strings the CALLER resolved. NONE of them may be a value
// this test binary's own host would produce: a console arg of "console=ttyS0",
// or an emulator binary that really exists, would let a host fact leaking back
// into up.go pass on the developer's machine and fail nowhere.
//
// The substrate reads like a QEMU one because that is the caller this suite
// stands in for, but "qemu-system-fake" is deliberately a binary no host has.
const (
	fakeSubstrate     = "linux/amd64, kvm, qemu-system-fake"
	fakeConsoleArg    = "console=ttyFAKE0"
	fakeVersionSource = "talos-" + imageTalosVersion + "-amd64.iso (ISO volume id)"
)

// upFixture builds an UpOptions wired to a recorder, a temp state dir and a
// buffer, plus the booted flag so "the guard ran before the VM was created"
// is assertable.
type upFixture struct {
	opts UpOptions
	rec  *recorder
	out  *strings.Builder
	dir  string
	// booted records whether Boot was called, and how many times.
	booted int
}

func newFixture(t *testing.T) *upFixture {
	t.Helper()

	f := &upFixture{
		rec: &recorder{},
		out: &strings.Builder{},
		dir: t.TempDir(),
	}

	f.opts = UpOptions{
		ClusterName:    "probe",
		StateDir:       f.dir,
		TalosEndpoint:  "127.0.0.1:50000",
		KubeEndpoint:   "https://127.0.0.1:6443",
		SystemDisk:     DiskRef{Serial: "talos-system"},
		DataDiskSerial: "talos-data",
		TalosVersion:   imageTalosVersion,
		VersionSource:  fakeVersionSource,
		Substrate:      fakeSubstrate,
		ConsoleArg:     fakeConsoleArg,
		Boot: func() (int, error) {
			f.booted++

			return 163166, nil
		},
		Out:   f.out,
		hooks: f.rec.hooks(),
	}

	return f
}

func (f *upFixture) run(t *testing.T) error {
	t.Helper()

	return Up(context.Background(), f.opts)
}

func (f *upFixture) mustRun(t *testing.T) string {
	t.Helper()

	if err := f.run(t); err != nil {
		t.Fatalf("Up: %s\n%s", redactErr(err), redact(f.out.String()))
	}

	return f.out.String()
}

// wants asserts every fragment is present, and dumps the (redacted) transcript
// once if any is missing.
func wants(t *testing.T, transcript string, fragments ...string) {
	t.Helper()

	for _, want := range fragments {
		if !strings.Contains(transcript, want) {
			t.Errorf("transcript does not contain %q\n%s", want, redact(transcript))
		}
	}
}

// announcedSteps is every step line a bring-up prints, in order. It is shared
// because a RESUMED bring-up has to print all ten of them too: steps it skips
// are announced as skipped, never dropped, so the numbering cannot silently
// close up and describe a sequence that did not run.
var announcedSteps = []string{
	"[ 1/10] platform",
	"[ 2/10] version",
	"[ 3/10] version guard",
	"[ 4/10] boot",
	"[ 5/10] maintenance",
	"[ 6/10] config",
	"[ 7/10] apply-config",
	"[ 8/10] bootstrap",
	"[ 9/10] kubeconfig",
	"[10/10] storage",
}

// stepsInOrder asserts every announced step is present, once, in order.
func stepsInOrder(t *testing.T, transcript string) {
	t.Helper()

	at := -1

	for _, step := range announcedSteps {
		i := strings.Index(transcript, step)
		if i < 0 {
			t.Fatalf("no %q line in the transcript\n%s", step, redact(transcript))
		}

		if i < at {
			t.Errorf("%q is printed out of order\n"+
				"  reason: the transcript is what an operator reads a bring-up by; steps that swap "+
				"places describe a bring-up that did not happen\n%s", step, redact(transcript))
		}

		at = i
	}
}

// The step line is the contract: the number, the total and the label. Asserting
// on the label alone lets two steps swap places and the suite stay green — and
// the ORDER is the thing an operator reads a bring-up transcript for.
func TestUpPrintsTheTenAnnouncedStepsInOrder(t *testing.T) {
	f := newFixture(t)
	transcript := f.mustRun(t)

	stepsInOrder(t, transcript)

	// A reason printed flush left reads as a step of its own, and the
	// transcript's whole shape is "the operation, then why". Every line inside
	// the numbered block is therefore indented past where a step line's text
	// begins.
	for _, line := range strings.Split(transcript[:strings.Index(transcript, "[10/10]")], "\n") {
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}

		if !strings.HasPrefix(line, "        ") {
			t.Errorf("a continuation line is not indented under its step: %q\n"+
				"  reason: at column zero it reads as a step of its own, and the reason stops belonging to the operation", line)
		}
	}

	// The operation each step performed, not just its name.
	wants(t, transcript,
		fakeSubstrate,
		fakeVersionSource+" -> "+imageTalosVersion,
		"machinery "+GeneratorVersion()+" >= image "+imageTalosVersion,
		"pid 163166", "api 127.0.0.1:50000",
		"controlplane.yaml", "talosconfig",
		"local-path-provisioner "+LocalPathVersion,
	)
}

// Step 1 and step 2 are the caller's lines now. This package cannot assemble
// either one: an accelerator and an emulator binary describe a QEMU guest, and
// an ISO volume id is not where a running node's version comes from.
func TestUpRendersSubstrateAndVersionFromOptions(t *testing.T) {
	f := newFixture(t)
	f.opts.Substrate = "baremetal, 192.168.1.50"
	f.opts.TalosVersion = imageTalosVersion
	f.opts.VersionSource = "the node's maintenance API"

	out := f.mustRun(t)

	if !strings.Contains(out, "baremetal, 192.168.1.50") {
		t.Errorf("step 1 did not print the caller's substrate line\n"+
			"  reason: cluster/ no longer knows what a hypervisor is, so an "+
			"accelerator and an emulator binary cannot come from here\n%s", redact(out))
	}

	if !strings.Contains(out, "the node's maintenance API -> "+imageTalosVersion) {
		t.Errorf("step 2 did not print the caller's version source\n"+
			"  reason: a baremetal node has no ISO to read a volume id from\n%s", redact(out))
	}
}

// CARRIED REQUIREMENT 1. CheckVersion returns (checked, err) and `checked` is
// the ONLY signal that the guard never ran: a pre-release volume id such as
// TALOS_V1_14_0_ALPHA reads as "" from InspectImageVersion, CheckVersion
// returns (false, nil), and a caller writing `_, err :=` re-disables the guard
// for exactly the images most likely to break config generation.
//
// The verdict is a REFUSAL, and it lands before Boot. GenerateConfig has no
// branch that accepts an empty version, so announcing this and continuing
// spends a VM, a state dir and the five-minute maintenance wait to arrive at a
// failure the ISO's volume id already proved.
func TestUpRefusesAnImageItCouldNotIdentifyBeforeBooting(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosVersion = ""

	err := f.run(t)
	if err == nil {
		t.Fatal("Up continued past an image whose Talos version could not be determined\n" +
			"  reason: GenerateConfig refuses an empty version unconditionally, so this arm is already fatal")
	}

	if f.booted != 0 {
		t.Errorf("the VM was booted %d times for an image the guard could not identify\n"+
			"  reason: failing here costs nothing; failing after the disk exists leaves residue", f.booted)
	}

	if f.rec.did("waitMaintenance") {
		t.Error("Up spent the maintenance budget on an image it had already proven it cannot configure")
	}

	transcript := f.out.String()

	// The operator must still learn WHY, and get the remedy — which lives in
	// the shared refusal, not in the transcript.
	wants(t, transcript,
		"[ 3/10] version guard",
		"REFUSED",
		"could not be determined",
		"TALOS_V1_14_0_ALPHA",
	)
	wants(t, err.Error(), "could not determine the Talos version", "TALOS_V1_13_7")

	// An unknown version must not read as a passing guard.
	if regexp.MustCompile(`(?m)^\[ 3/10\] version guard .*\bok\b`).MatchString(transcript) {
		t.Errorf("the version guard reports ok for an image it could not identify\n%s", redact(transcript))
	}

	// And step 2 must say so too. Printing the empty string leaves a line
	// reading "talos.iso -> (ISO volume id)", which is a blank where the one
	// value the next step depends on should be.
	wants(t, transcript, "-> UNKNOWN")
}

// The other side of it: an image that WAS identified must not print the
// refusal, or the warning becomes noise and stops being read.
func TestUpDoesNotAnnounceASkippedGuardForAKnownImage(t *testing.T) {
	transcript := newFixture(t).mustRun(t)

	for _, unwanted := range []string{"could not be determined", "REFUSED"} {
		if strings.Contains(transcript, unwanted) {
			t.Errorf("a fully identified image printed %q\n"+
				"  reason: a warning that fires on every run is a warning nobody reads", unwanted)
		}
	}
}

// The guard exists to stop a config being generated for a Talos that does not
// exist. Refusing AFTER the VM has been created leaves residue behind for a
// failure that cost nothing to see coming.
func TestUpRefusesAnImageNewerThanTheGeneratorBeforeBooting(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosVersion = "v1.99.0"

	err := f.run(t)
	if err == nil {
		t.Fatal("Up generated a cluster from an image newer than the generator\n" +
			"  reason: exceeding the version contract does not error, it silently emits a config for a Talos that does not exist")
	}

	if f.booted != 0 {
		t.Errorf("the VM was booted %d times before the version guard refused\n"+
			"  reason: failing here costs nothing; failing after the disk exists leaves residue", f.booted)
	}

	if f.rec.did("generateConfig") {
		t.Error("a config was generated for an image the guard refused")
	}
}

// CARRIED REQUIREMENT 2. `dataDisk: 40` — the unit omitted — decodes as a
// float64, specDataDisk reads it as "not set", and there is no disk and no
// error. Without this line the first sign of the typo is a PVC that stays
// Pending an hour later.
func TestUpAnnouncesStorageWasSkippedWithoutADataDisk(t *testing.T) {
	f := newFixture(t)
	f.opts.DataDiskSerial = ""

	transcript := f.mustRun(t)

	wants(t, transcript,
		"[10/10] storage",
		"skipped (no dataDisk and no ephemeralMaxSize)",
	)

	if f.rec.did("installStorage") {
		t.Error("storage was installed with no data disk\n" +
			"  reason: PVCs would land on EPHEMERAL beside etcd, which is the failure the data disk exists to prevent")
	}

	// The two halves of storage must not disagree: no data disk means no user
	// volume in the config either.
	if f.rec.input.DataDiskSerial != "" {
		t.Errorf("GenerateConfig was asked for a user volume on %q with no data disk",
			f.rec.input.DataDiskSerial)
	}

	if strings.Contains(transcript, "userVolume:") {
		t.Errorf("step 6 announces a user volume with no data disk\n%s", redact(transcript))
	}
}

// The four reasons below are each a DOCUMENTED failure, not commentary. A step
// that announces the operation and swallows the reason turns this tool back
// into the black box it exists not to be.
func TestUpAnnouncesTheReasonForEveryNonObviousDecision(t *testing.T) {
	transcript := newFixture(t).mustRun(t)

	for _, tc := range []struct {
		what   string
		wants  []string
		reason string
	}{
		{
			"diskSelector by serial",
			[]string{`diskSelector: serial "talos-system"`, "coin flip"},
			"a size matcher picks between the OS target and the data disk once both are large",
		},
		{
			"installer pinned to the image",
			[]string{"installer: ghcr.io/siderolabs/installer:" + imageTalosVersion, "cross-version"},
			"left unset, Talos defaults the installer to OUR version and a fresh install becomes a silent upgrade",
		},
		{
			"console arg for this host",
			[]string{"console=ttyFAKE0", "own cmdline"},
			"the installed system writes its own cmdline and goes silent on serial without it",
		},
		{
			"bootstrap fires while booting",
			[]string{"booting", "running", "deadlock"},
			"waiting for 'running' can never open: the node cannot reach running until etcd exists, and bootstrap is what creates etcd",
		},
	} {
		for _, want := range tc.wants {
			if !strings.Contains(transcript, want) {
				t.Errorf("%s: the transcript does not say %q\n  reason: %s\n%s",
					tc.what, want, tc.reason, redact(transcript))
			}
		}
	}
}

// Every node fact Up is GIVEN reaches GenerateConfig unaltered, and the two
// worth a test of their own are the console arg and the API address. The
// console arg is the caller's — up.go no longer derives one, and a literal
// here would read correctly on amd64 and put an arm64 node's console on a UART
// it does not have. The address is DERIVED, from the endpoint, which is the
// one field in this struct nobody hands over ready-made.
func TestUpCarriesTheCallersNodeFactsIntoTheConfig(t *testing.T) {
	f := newFixture(t)
	// NOT the fixture's loopback endpoint. APIAddress is asserted below, and
	// against 127.0.0.1:50000 a hardcoded "127.0.0.1" written beside the
	// endpoint in up.go is indistinguishable from deriving it — which is the
	// exact defect the derivation exists to remove.
	f.opts.TalosEndpoint = "192.168.1.50:50000"
	f.mustRun(t)

	if f.rec.input.ConsoleArg != "console=ttyFAKE0" {
		t.Errorf("GenerateConfig got ConsoleArg %q, want the caller's console=ttyFAKE0\n"+
			"  reason: hardcoding ttyS0 gives an arm64 node a serial console it does not have",
			f.rec.input.ConsoleArg)
	}

	if f.rec.input.SystemDisk != (DiskRef{Serial: "talos-system"}) || f.rec.input.DataDiskSerial != "talos-data" {
		t.Errorf("GenerateConfig got disks %v/%q, want the caller's talos-system/talos-data",
			f.rec.input.SystemDisk, f.rec.input.DataDiskSerial)
	}

	if f.rec.input.TalosVersion != imageTalosVersion {
		t.Errorf("GenerateConfig got TalosVersion %q, want the IMAGE's "+imageTalosVersion+"\n"+
			"  reason: the installer tag is written to disk; the generator's own version there is a cross-version install",
			f.rec.input.TalosVersion)
	}

	if f.rec.input.Endpoint != "https://127.0.0.1:6443" {
		t.Errorf("GenerateConfig got Endpoint %q, want the Kubernetes API URL", f.rec.input.Endpoint)
	}

	if f.rec.input.APIAddress != "192.168.1.50" {
		t.Errorf("GenerateConfig got APIAddress %q, want the host part of TalosEndpoint 192.168.1.50\n"+
			"  reason: apid's certificate must name the address the client dials; an address written "+
			"beside the endpoint instead of derived from it is a TLS failure minutes into a bring-up",
			f.rec.input.APIAddress)
	}

	if f.rec.input.ClusterName != "probe" {
		t.Errorf("GenerateConfig got ClusterName %q, want probe\n"+
			"  reason: name and endpoint are adjacent strings; swapped, everything still generates", f.rec.input.ClusterName)
	}
}

// The paths are printed because hunting for them is the friction this replaces,
// and the three hardened defaults are printed because a Talos cluster is
// production-shaped and a `kind` habit fails against it with no explanation.
func TestUpPrintsTheExportLinesAndTheHardenedDefaults(t *testing.T) {
	f := newFixture(t)
	transcript := f.mustRun(t)

	wants(t, transcript,
		"export TALOSCONFIG="+filepath.Join(f.dir, "talosconfig"),
		"export KUBECONFIG="+filepath.Join(f.dir, "kubeconfig"),
		"kubectl get nodes",
		// taint removed, and WHY
		"allowSchedulingOnControlPlanes",
		"topology correction",
		// PodSecurity still enforced, and HOW to opt a namespace out
		"PodSecurity",
		"baseline",
		"pod-security.kubernetes.io/enforce=privileged",
		// storage state, including that PVCs do not survive teardown
		"does not survive",
	)
}

// The storage note has to tell the truth in BOTH shapes, or it is worse than
// no note: an operator told a StorageClass exists writes a PVC and waits.
func TestUpsStorageNoteMatchesReality(t *testing.T) {
	f := newFixture(t)
	f.opts.DataDiskSerial = ""

	transcript := f.mustRun(t)

	if strings.Contains(transcript, "default StorageClass") {
		t.Errorf("the summary claims a default StorageClass with no data disk\n%s", redact(transcript))
	}

	wants(t, transcript, "no StorageClass")
}

// Every artifact here is secret material: the control plane config carries five
// certificate authorities and the machine token, the talosconfig and kubeconfig
// each carry a CA and a client key, and secrets.yaml is the bundle. 0600 is not
// advisory — the state dir sits under $HOME beside serial.log.
func TestUpWritesEveryArtifactAt0600(t *testing.T) {
	// The verdict must not depend on the runner's umask. Under the usual 022 a
	// 0644 write lands as 0644 and this test fails; under 077 the same write
	// lands as 0600 and it passes — one mutant, two answers, decided by an
	// environment variable nobody set on purpose. Zeroed here so the assertion
	// is about the code.
	restore := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(restore) })

	f := newFixture(t)

	// A re-run over an existing state dir must TIGHTEN the mode. os.WriteFile
	// does not chmod a file that already exists, so a kubeconfig left at 0644
	// by anything else stays world-readable without this.
	loose := filepath.Join(f.dir, "kubeconfig")
	if err := os.WriteFile(loose, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.mustRun(t)

	for name, want := range map[string]string{
		"controlplane.yaml": fakeControlPlane,
		"talosconfig":       fakeTalosconfig,
		"secrets.yaml":      fakeSecrets,
		"kubeconfig":        fakeKubeconfig,
	} {
		path := filepath.Join(f.dir, name)

		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s was not written: %v\n"+
				"  reason: artifacts live in the state dir so -destroy sweeps them and secrets do not outlive the cluster", name, err)

			continue
		}

		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", name, mode)
		}

		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		// Compared without printing either side: both are secret-shaped.
		if string(b) != want {
			t.Errorf("%s holds the wrong artifact (%d bytes, want %d)\n"+
				"  reason: writing the talosconfig into controlplane.yaml produces a node that never installs",
				name, len(b), len(want))
		}
	}
}

// Two earlier tasks on this branch shipped leaks that only a guard test caught.
// Up handles four secret artifacts and prints a transcript, which is the
// obvious place for the fifth.
func TestUpNeverPrintsSecrets(t *testing.T) {
	secretsOf := []string{fakeControlPlane, fakeTalosconfig, fakeSecrets, fakeKubeconfig}

	t.Run("on-success", func(t *testing.T) {
		transcript := newFixture(t).mustRun(t)

		for _, secret := range secretsOf {
			if strings.Contains(transcript, secret) {
				t.Errorf("a secret artifact was printed to the transcript (%d chars)\n"+
					"  reason: the transcript goes to a terminal, a CI log and whatever gets pasted into an issue",
					len(secret))
			}
		}
	})

	// A RESUMED bring-up reads a talosconfig off disk and announces that it
	// did, which is a new place for the file's contents to end up in a line
	// that is meant to name it.
	t.Run("on-a-resumed-run", func(t *testing.T) {
		f := newFixture(t)
		writeTalosconfig(t, f.dir)

		transcript := f.mustRun(t)

		if strings.Contains(transcript, existingTalosconfig) {
			t.Errorf("the talosconfig read from the state dir was printed to the transcript (%d chars)\n"+
				"  reason: it is a cluster CA and a client key; the step may name the file, never its contents",
				len(existingTalosconfig))
		}
	})

	// Every step after the config exists holds secret material in a local, and
	// a failure is where an error message goes looking for context to add.
	for _, step := range []string{"applyConfig", "waitBootstrapReady", "bootstrap", "kubeconfig", "waitNodeReady", "installStorage"} {
		t.Run("when-"+step+"-fails", func(t *testing.T) {
			f := newFixture(t)
			f.rec.failAt = step

			err := f.run(t)
			if err == nil {
				t.Fatalf("a failing %s did not fail the bring-up", step)
			}

			for _, secret := range secretsOf {
				if strings.Contains(err.Error(), secret) || strings.Contains(f.out.String(), secret) {
					t.Errorf("a secret artifact reached the output of a failing %s (%d chars)", step, len(secret))
				}
			}
		})
	}
}

// A bring-up that dies half way leaves a VM and a state dir. Re-running `up` is
// now the first thing to try — it resumes from whatever the machine reached —
// so the message has to say that AND name the one case a retry cannot repair:
// a config written to the state dir but never accepted by the node, where the
// state dir says "configured" and the node is still in maintenance mode.
func TestUpSaysHowToRecoverFromAMidFlightFailure(t *testing.T) {
	f := newFixture(t)
	f.rec.failAt = "bootstrap"

	err := f.run(t)
	if err == nil {
		t.Fatal("a failing bootstrap did not fail the bring-up")
	}

	for _, want := range []string{"tinq up", "tinq destroy", "maintenance mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %s\n"+
				"  reason: the retry that works and the retry that waits out a ten-minute timeout are different commands, "+
				"and this message is the only thing that tells them apart", want, redactErr(err))
		}
	}

	// The flag spellings are gone: these are cobra verbs now, and a message
	// telling an operator to run `tinq -destroy` sends them to a usage error.
	for _, stale := range []string{"-destroy", "-up "} {
		if strings.Contains(err.Error(), stale) {
			t.Errorf("the failure still tells the operator to run %q: %s", stale, redactErr(err))
		}
	}
}

// upOperations is every operation Up performs against a node or a cluster, in
// the order the node requires, paired with the step line each one is announced
// under. It drives the two tests below, so a hook added without an announcement
// — or announced without being checked — cannot slip through either.
var upOperations = []struct {
	op   string
	step string
}{
	{"waitMaintenance", "[ 5/10] maintenance"},
	{"generateConfig", "[ 6/10] config"},
	{"applyConfig", "[ 7/10] apply-config"},
	{"waitBootstrapReady", "[ 7/10] apply-config"},
	{"bootstrap", "[ 8/10] bootstrap"},
	{"kubeconfig", "[ 9/10] kubeconfig"},
	{"waitNodeReady", "[ 9/10] kubeconfig"},
	{"installStorage", "[10/10] storage"},
}

// A failed step must fail the bring-up, must not be announced as done, and
// nothing after it may run.
//
// Every operation is exercised, not one representative: a swallowed error is
// invisible in the happy path, and "the wait for the maintenance API returned
// an error and we applied the config anyway" is a bring-up that then fails four
// steps later against a node that was never listening.
func TestUpStopsAtTheFirstFailedStep(t *testing.T) {
	for i, tc := range upOperations {
		t.Run(tc.op, func(t *testing.T) {
			f := newFixture(t)
			f.rec.failAt = tc.op

			err := f.run(t)
			if err == nil {
				t.Fatalf("a failing %s did not fail the bring-up\n"+
					"  reason: a swallowed error here is announced as a step that succeeded, and "+
					"the transcript becomes something an operator debugs against instead of from", tc.op)
			}

			transcript := f.out.String()

			if strings.Contains(transcript, tc.step) {
				t.Errorf("%q was announced although %s failed\n%s", tc.step, tc.op, redact(transcript))
			}

			for _, later := range upOperations[i+1:] {
				if f.rec.did(later.op) {
					t.Errorf("%s ran after %s failed", later.op, tc.op)
				}
			}
		})
	}
}

// Both endpoints are the address a client dials to reach this node — the host
// side of a forward for a VM, the node's own address for adopted hardware. A
// missing one is not discovered until a wait spends its whole budget on an
// address that is not there.
func TestUpRefusesWithoutTheAPIEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clear func(*UpOptions)
		want  string
	}{
		{"talos", func(o *UpOptions) { o.TalosEndpoint = "" }, "50000"},
		{"kubernetes", func(o *UpOptions) { o.KubeEndpoint = "" }, "6443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.clear(&f.opts)

			err := f.run(t)
			if err == nil {
				t.Fatalf("Up ran with no %s endpoint", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the API's port %s: %s\n"+
					"  reason: the port is what tells the two endpoints apart, and the message is the "+
					"only thing that says which one is missing",
					tc.want, redactErr(err))
			}

			if f.booted != 0 {
				t.Error("the VM was booted before the endpoints were checked")
			}
		})
	}
}

// apiAddress decides the ONE value apid's certificate is issued for, so each of
// its refusals is the difference between an error here and a TLS handshake
// failure minutes into a bring-up. The empty-host case is the one worth a test
// of its own: ":50000" splits WITHOUT an error, host just comes back "", and
// without the guard that generates a certificate naming nothing.
func TestAPIAddressIsTheHostPartOfTheEndpoint(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		want     string
	}{
		{"127.0.0.1:50000", "127.0.0.1"},
		{"192.168.1.50:50000", "192.168.1.50"},
		{"[fd00::1]:50000", "fd00::1"},
	} {
		got, err := apiAddress(tc.endpoint)
		if err != nil {
			t.Errorf("apiAddress(%q): %s", tc.endpoint, err)
			continue
		}

		if got != tc.want {
			t.Errorf("apiAddress(%q) = %q, want %q\n"+
				"  reason: this is what apid's certificate is issued for, and it must be what the client dials",
				tc.endpoint, got, tc.want)
		}
	}

	for _, endpoint := range []string{"", "192.168.1.50", ":50000"} {
		if got, err := apiAddress(endpoint); err == nil {
			t.Errorf("apiAddress(%q) = %q, want a refusal\n"+
				"  reason: a certificate issued for %q names nothing a client can dial, and that "+
				"surfaces as a handshake failure with nothing pointing at the endpoint",
				endpoint, got, got)
		}
	}
}

// Both defaults in Up are invisible to every test above, because every test
// above supplies both — and their absence is not a wrong answer, it is a nil
// dereference in production only.
//
// The version is a FIELD now rather than something a hook reads off an ISO, so
// nothing before step 5 touches a hook at all and the only way to prove the
// hooks default is to REACH one. The context is cancelled before the call, so
// the real waitMaintenance gives up on its first probe instead of spending its
// five-minute budget on an address nothing is listening on.
//
// Both proofs are structural rather than textual: Boot running means steps 1 to
// 4 printed, so Out nil resolved to os.Stdout (a nil writer panics in p.step),
// and an ERROR back from step 5 means the real wait ran, so hooks nil resolved
// to realHooks (a nil hooks panics, it does not fail).
func TestUpDefaultsToStdoutAndTheRealOperations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	booted := false

	err := Up(ctx, UpOptions{
		ClusterName: "probe",
		StateDir:    t.TempDir(),
		// Nothing is listening here and nothing needs to be.
		TalosEndpoint: "127.0.0.1:1",
		KubeEndpoint:  "https://127.0.0.1:6443",
		SystemDisk:    DiskRef{Serial: "talos-system"},
		TalosVersion:  imageTalosVersion,
		VersionSource: fakeVersionSource,
		Substrate:     fakeSubstrate,
		ConsoleArg:    fakeConsoleArg,
		Boot: func() (int, error) {
			booted = true

			return 163166, nil
		},
		// Out and hooks are deliberately left nil.
	})

	if !booted {
		t.Fatal("Up never reached step 4 with Out left nil\n" +
			"  reason: a nil io.Writer is a panic in p.step, not a quiet no-op")
	}

	if err == nil {
		t.Fatal("step 5 succeeded against an address nothing is listening on\n" +
			"  reason: only the REAL waitMaintenance can fail here; a nil hooks panics")
	}
}

// realHooks is the wiring, and a nil entry in it is a nil call at whichever
// step reaches it — five minutes into a bring-up, on a node that is by then
// halfway installed.
func TestRealHooksAreAllWired(t *testing.T) {
	h := reflect.ValueOf(*realHooks())

	for i := range h.NumField() {
		if h.Field(i).IsNil() {
			t.Errorf("realHooks().%s is nil", h.Type().Field(i).Name)
		}
	}

	if h.NumField() == 0 {
		t.Fatal("upHooks has no fields; this test is asserting nothing")
	}
}

// The artifacts are the point of the state dir, so a write that fails must stop
// the bring-up rather than continue into a cluster nobody can then reach: a
// talosconfig that was never written is a cluster with no way in.
func TestUpReportsAFailureToWriteAnArtifact(t *testing.T) {
	t.Run("state-dir-missing", func(t *testing.T) {
		f := newFixture(t)
		f.opts.StateDir = filepath.Join(f.dir, "not-created")

		err := f.run(t)
		if err == nil {
			t.Fatal("Up continued after failing to write the generated config")
		}

		if f.rec.did("applyConfig") {
			t.Error("a config was applied that was never written to the state dir\n" +
				"  reason: the node then installs from a config the operator has no copy of")
		}

		if strings.Contains(f.out.String(), "[ 6/10] config") {
			t.Errorf("step 6 announced \"wrote controlplane.yaml, talosconfig, secrets.yaml\" and then failed to\n"+
				"  reason: announcing before doing turns the transcript into something to debug rather than debug from\n%s",
				redact(f.out.String()))
		}
	})

	// Step 9's write has its own guard, and the happy path cannot reach it:
	// step 6 writes to the same directory and succeeds first. Blocking exactly
	// one filename is what makes the later guard reachable.
	t.Run("kubeconfig-path-blocked", func(t *testing.T) {
		f := newFixture(t)

		blocked := filepath.Join(f.dir, "kubeconfig")
		if err := os.MkdirAll(filepath.Join(blocked, "occupied"), 0o755); err != nil {
			t.Fatal(err)
		}

		err := f.run(t)
		if err == nil {
			t.Fatal("Up continued after failing to write the kubeconfig")
		}

		if _, statErr := os.Stat(filepath.Join(f.dir, "controlplane.yaml")); statErr != nil {
			t.Fatalf("step 6 did not get far enough for this to be step 9's guard: %v", statErr)
		}

		if f.rec.did("installStorage") {
			t.Error("storage was installed with no kubeconfig on disk")
		}

		if strings.Contains(f.out.String(), "[ 9/10] kubeconfig") {
			t.Errorf("step 9 announced a kubeconfig it failed to write\n%s", redact(f.out.String()))
		}
	})
}

// Boot failing is the one error that is NOT mid-flight residue in the sense the
// note describes, and it still has to come back as an error rather than a
// transcript that stops silently. Host detection is no longer among the things
// that can fail here at all: the caller resolves its own facts and hands over
// the results, so a host with no accelerator fails before Up is ever called.
func TestUpReportsAFailureToBoot(t *testing.T) {
	f := newFixture(t)
	f.opts.Boot = func() (int, error) { return 0, errors.New("qemu: exit status 1") }

	err := f.run(t)
	if err == nil {
		t.Fatal("Up continued with no VM")
	}

	if !strings.Contains(err.Error(), "qemu") {
		t.Errorf("the boot failure was replaced rather than reported: %s", redactErr(err))
	}

	if f.rec.did("waitMaintenance") {
		t.Error("Up waited for the maintenance API of a VM that never started")
	}
}

// Ordering inside a step is invisible in the transcript and load-bearing
// everywhere else: applying the config before the maintenance API answers gets
// a connection refused, and bootstrapping before the installed system is back
// gets a certificate from a node still in maintenance mode.
func TestUpRunsTheOperationsInTheOrderTheNodeRequires(t *testing.T) {
	f := newFixture(t)
	f.mustRun(t)

	want := []string{
		"waitMaintenance",
		"generateConfig",
		"applyConfig",
		"waitBootstrapReady",
		"bootstrap",
		"kubeconfig",
		"waitNodeReady",
		"installStorage",
	}

	if len(f.rec.called) != len(want) {
		t.Fatalf("operations = %v, want %v", f.rec.called, want)
	}

	for i := range want {
		if f.rec.called[i] != want[i] {
			t.Errorf("operation %d = %q, want %q\n"+
				"  reason: %s", i, f.rec.called[i], want[i], orderReason(want[i]))
		}
	}
}

// Every hook takes a []byte of secret material, and there are four different
// ones in flight. A swap COMPILES, and each swap is a failure the node reports
// rather than this package: the talosconfig applied as a machine config is
// rejected by a node already installing, and the machine config handed to the
// storage installer is a kubeconfig parse error nine steps in.
func TestUpHandsEachOperationTheRightArtifact(t *testing.T) {
	f := newFixture(t)
	f.mustRun(t)

	for _, tc := range []struct {
		op, want, describe string
	}{
		{"applyConfig", fakeControlPlane, "the machine config is what a node in maintenance mode installs from"},
		{"waitBootstrapReady", fakeTalosconfig, "the wait authenticates with the cluster PKI, which only the talosconfig carries"},
		{"bootstrap", fakeTalosconfig, "bootstrap is a Talos API call, not a Kubernetes one"},
		{"kubeconfig", fakeTalosconfig, "the kubeconfig is FETCHED over the Talos API using the talosconfig"},
		{"waitNodeReady", fakeKubeconfig, "node readiness is the Kubernetes API's answer, not Talos's"},
		{"installStorage", fakeKubeconfig, "the manifest goes to the Kubernetes API"},
	} {
		got, ok := f.rec.payload[tc.op]
		if !ok {
			t.Errorf("%s was never called", tc.op)

			continue
		}

		// Lengths and identity only: printing either side is the leak the
		// guard test below exists to prevent.
		if string(got) != tc.want {
			t.Errorf("%s was handed the wrong artifact (%d bytes, want the %d-byte one)\n  reason: %s",
				tc.op, len(got), len(tc.want), tc.describe)
		}
	}
}

func orderReason(op string) string {
	switch op {
	case "waitMaintenance":
		return "the config cannot be applied before the maintenance API answers"
	case "waitBootstrapReady":
		return "bootstrap needs the INSTALLED system's apid, which maintenance mode cannot satisfy"
	case "installStorage":
		return "the provisioner cannot be applied before the node is Ready"
	}

	return "the node requires this order"
}

// A refusal from the version guard must reach the operator with the guard's own
// message — that message is where the remedy is.
func TestUpKeepsTheVersionGuardsExplanation(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosVersion = "v1.99.0"

	err := f.run(t)
	if err == nil {
		t.Fatal("no refusal")
	}

	wants(t, err.Error(), "v1.99.0", GeneratorVersion())
}

// ── D8: a bring-up starts from wherever the machine already is ──────────────
//
// `tinq stop` keeps a machine's disks, so the most natural next command is
// `tinq up` — and before this it could not work. The node boots the system it
// INSTALLED, never re-enters maintenance mode, and step 5 spent its entire
// five-minute budget proving that before failing.
//
// The discriminator is the talosconfig in the state dir, and what it is matters
// to every test below: it is a CREDENTIAL, not a status. Its presence is what
// makes an authenticated call possible at all; the claim that the node is
// configured still comes from whether that call's handshake succeeds, which a
// node in maintenance mode cannot fake.

// writeTalosconfig leaves behind what a previous `up` leaves behind. It is the
// ONLY difference between the two paths.
func writeTalosconfig(t *testing.T, dir string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, "talosconfig"), []byte(existingTalosconfig), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The read BOTH `up` and `adopt` gate on. It is one function because the two
// must agree on what "configured" means: a disagreement is adopt waiting out
// its full maintenance budget for an API an installed node never serves again,
// with nothing in the output naming the cause.
//
// The three outcomes are not two: a missing file is an ANSWER — never
// configured — and everything else is a failure that must not be read as one.
func TestReadTalosconfigTellsTheThreeCasesApart(t *testing.T) {
	dir := t.TempDir()

	if _, configured, err := ReadTalosconfig(dir); err != nil || configured {
		t.Errorf("an empty state dir read as configured=%v, err=%v; want false and no error\n"+
			"  reason: never configured is an answer, and an error here would refuse every "+
			"fresh machine", configured, err)
	}

	writeTalosconfig(t, dir)

	got, configured, err := ReadTalosconfig(dir)
	if err != nil || !configured {
		t.Fatalf("a state dir holding a talosconfig read as configured=%v, err=%v", configured, err)
	}

	// Compared, never printed: it is a cluster CA and a client key.
	if string(got) != existingTalosconfig {
		t.Errorf("ReadTalosconfig returned %d bytes, want the %d-byte credential on disk",
			len(got), len(existingTalosconfig))
	}

	// A directory in its place. Read as "not configured" this becomes a
	// maintenance wait against a node that may well be installed.
	blocked := t.TempDir()
	if err := os.MkdirAll(filepath.Join(blocked, "talosconfig", "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, configured, err := ReadTalosconfig(blocked); err == nil || configured {
		t.Errorf("an unreadable talosconfig read as configured=%v, err=%v; want a refusal\n"+
			"  reason: silently reading it as absent sends adopt into a ten-minute wait for "+
			"maintenance mode", configured, err)
	}
}

// A machine that has been configured before must not be sent back through
// maintenance mode, config generation or apply-config: the first waits for a
// state the node has left forever, and the other two mint a NEW secrets bundle
// whose CA the installed node has never heard of.
func TestUpSkipsConfigurationForAMachineThatAlreadyHasATalosconfig(t *testing.T) {
	f := newFixture(t)
	writeTalosconfig(t, f.dir)

	transcript := f.mustRun(t)

	for _, op := range []string{"waitMaintenance", "generateConfig", "applyConfig"} {
		if f.rec.did(op) {
			t.Errorf("%s ran for a machine that was already configured\n"+
				"  reason: %s", op, resumeReason(op))
		}
	}

	if !f.rec.did("waitBootstrapReady") {
		t.Error("nothing waited for the node to be reachable before bootstrap\n" +
			"  reason: the VM was just started; bootstrapping into a booting node fails on a dial")
	}

	// The credential in flight is the one from DISK. A resumed run that used
	// freshly generated material would authenticate against a CA the node does
	// not trust, and every call after this point would fail on the handshake.
	if got := string(f.rec.payload["bootstrap"]); got != existingTalosconfig {
		t.Errorf("bootstrap was handed a %d-byte talosconfig, want the %d-byte one from the state dir\n"+
			"  reason: a regenerated bundle is a NEW cluster CA, and the installed node trusts the old one",
			len(got), len(existingTalosconfig))
	}

	// And nothing overwrote it. secrets.yaml and controlplane.yaml are the
	// same story: rewriting them buries the material the node actually holds.
	b, err := os.ReadFile(filepath.Join(f.dir, "talosconfig"))
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != existingTalosconfig {
		t.Errorf("the talosconfig in the state dir was rewritten (%d bytes, was %d)\n"+
			"  reason: it is the only way back into the installed node", len(b), len(existingTalosconfig))
	}

	// The run still finishes the cluster half: kubeconfig, node Ready, storage.
	for _, op := range []string{"bootstrap", "kubeconfig", "waitNodeReady", "installStorage"} {
		if !f.rec.did(op) {
			t.Errorf("%s never ran on a resumed bring-up\n"+
				"  reason: the point of `up` is a Ready node with somewhere to put a PVC, from whatever state it starts in", op)
		}
	}

	stepsInOrder(t, transcript)
}

func resumeReason(op string) string {
	switch op {
	case "waitMaintenance":
		return "the node boots the system it installed and never re-enters maintenance mode, so this can only time out"
	case "generateConfig":
		return "generation mints a fresh secrets bundle, and its CA is not the one the installed node was given"
	}

	return "the config is already on the node; applying another would install over a running system"
}

// The transcript must say WHICH steps did not run and WHY. Silently renumbering
// or leaving gaps turns the one artifact an operator reads a bring-up by into
// something they have to reverse-engineer.
func TestUpAnnouncesTheStepsAResumedBringUpSkips(t *testing.T) {
	f := newFixture(t)
	writeTalosconfig(t, f.dir)

	transcript := f.mustRun(t)

	wants(t, transcript,
		"[ 5/10] maintenance", "[ 6/10] config", "[ 7/10] apply-config",
		// each skip named as a skip
		"skipped",
		// and the discriminator explained, in the operator's terms
		"talosconfig",
		// the reason maintenance can never answer again
		"maintenance mode",
		// the reason regenerating would be worse than useless
		"CA",
	)

	// A skipped step must not claim work it did not do.
	for _, lie := range []string{
		"wrote controlplane.yaml, talosconfig, secrets.yaml",
		"reachable after",
		"installing... rebooting...",
	} {
		if strings.Contains(transcript, lie) {
			t.Errorf("a resumed bring-up printed %q\n"+
				"  reason: the step did not run; announcing it makes the transcript something to debug rather than debug from\n%s",
				lie, redact(transcript))
		}
	}
}

// The other side: a machine with NO talosconfig is a machine nothing has ever
// configured — an `apply` machine, or a fresh one — and it must take the
// original path unchanged. TestUpRunsTheOperationsInTheOrderTheNodeRequires
// asserts the whole sequence; this one names the three steps D8 could have
// stolen from it, so a discriminator inverted by a missing `!` cannot pass.
func TestUpConfiguresAMachineWithNoTalosconfig(t *testing.T) {
	f := newFixture(t)

	if _, err := os.Stat(filepath.Join(f.dir, "talosconfig")); !os.IsNotExist(err) {
		t.Fatalf("the fixture state dir already holds a talosconfig; this test asserts nothing")
	}

	transcript := f.mustRun(t)

	for _, op := range []string{"waitMaintenance", "generateConfig", "applyConfig"} {
		if !f.rec.did(op) {
			t.Errorf("%s did not run for a machine that was never configured\n"+
				"  reason: nothing else applies a machine config, and a node in maintenance mode never installs without one", op)
		}
	}

	if strings.Contains(transcript, "skipped (already configured)") {
		t.Errorf("a never-configured machine was treated as resumable\n%s", redact(transcript))
	}
}

// ── D9: bootstrap is ATTEMPTED, never probed ────────────────────────────────
//
// `up` applies the config, waits out the reboot, and only THEN bootstraps etcd.
// A machine stopped inside that window comes back with apid serving the cluster
// PKI — so the authenticated wait succeeds — and with no etcd at all. Skipping
// bootstrap on the strength of that wait hangs forever in step 9 against a node
// that can never report Ready.

// alreadyBootstrappedError is exactly what a node returns for a second
// bootstrap, wrapped the way bootstrapEtcd wraps it. Source, Talos v1.13.7,
// internal/app/machined/internal/server/v1alpha1/v1alpha1_server.go:457:
//
//	if entries, _ := os.ReadDir(constants.EtcdDataPath); len(entries) > 0 {
//		return nil, status.Error(codes.AlreadyExists, "etcd data directory is not empty")
//	}
func alreadyBootstrappedError() error {
	return fmt.Errorf("bootstrapping etcd: %w",
		status.Error(codes.AlreadyExists, "etcd data directory is not empty"))
}

// preconditionError is the node's OTHER refusal, and unlike AlreadyExists it is
// TRANSIENT. Talos v1.13.7 raises it from two places that both clear on their
// own — v1alpha1_server.go:443, gated on IsBootstrapAllowed(), which
// v1alpha1_runtime.go:249 documents as "checks for CRI to be up"; and
// v1alpha1_server.go:454, "time is not in sync yet".
//
// MEASURED ON HARDWARE: a first adopt of the 192.168.1.170 node passed the
// authenticated-API gate after 2s and then died here, because apid serves the
// cluster PKI before containerd has finished starting. Re-running adopt
// bootstrapped fine, which is the definition of transient.
func preconditionError() error {
	return status.Error(codes.FailedPrecondition, "bootstrap is not available yet")
}

func TestBootstrapWithRetryOutlastsATransientPrecondition(t *testing.T) {
	var calls int

	err := bootstrapWithRetry(context.Background(), 30*time.Second, func(context.Context) error {
		calls++
		if calls < 3 {
			return preconditionError()
		}

		return nil
	})
	if err != nil {
		t.Fatalf("bootstrapWithRetry gave up on a precondition that cleared: %v\n"+
			"  reason: apid answers before containerd is up, so the FIRST bootstrap on real "+
			"hardware routinely lands too early", err)
	}

	if calls != 3 {
		t.Errorf("the bootstrap call was made %d times, want 3", calls)
	}
}

// AlreadyExists is the caller's SUCCESS signal, so retrying it would spend the
// whole budget and then return a timeout — turning the idempotent path into a
// five-minute hang followed by a failure against a healthy cluster.
func TestBootstrapWithRetryReturnsAlreadyExistsImmediately(t *testing.T) {
	var calls int

	started := time.Now()
	err := bootstrapWithRetry(context.Background(), 30*time.Second, func(context.Context) error {
		calls++

		return status.Error(codes.AlreadyExists, "etcd data directory is not empty")
	})

	if calls != 1 {
		t.Errorf("the bootstrap call was made %d times, want 1 — AlreadyExists cannot clear", calls)
	}

	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("bootstrapWithRetry spent %s on AlreadyExists, want an immediate return", elapsed)
	}

	// The whole point of returning early: Up's idempotent path still recognises it.
	if !alreadyBootstrapped(err) {
		t.Errorf("alreadyBootstrapped could not see the code through the retry wrapper: %v\n"+
			"  reason: step 8 reads this to tell a healthy re-run from a real failure", err)
	}
}

// Everything that is not a precondition is a real failure, and spending the
// budget on it delays the report without changing it.
func TestBootstrapWithRetryDoesNotRetryOrdinaryFailures(t *testing.T) {
	var calls int

	started := time.Now()
	err := bootstrapWithRetry(context.Background(), 30*time.Second, func(context.Context) error {
		calls++

		return errors.New("connection refused")
	})
	if err == nil {
		t.Fatal("bootstrapWithRetry reported a connection failure as success")
	}

	if calls != 1 {
		t.Errorf("the bootstrap call was made %d times, want 1", calls)
	}

	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("bootstrapWithRetry spent %s on an ordinary failure, want an immediate return", elapsed)
	}
}

// A precondition that never clears is a real failure too, and the message has
// to carry the node's own words rather than a bare timeout.
func TestBootstrapWithRetryGivesUpOnAPreconditionThatNeverClears(t *testing.T) {
	err := bootstrapWithRetry(context.Background(), 3*time.Second, func(context.Context) error {
		return preconditionError()
	})
	if err == nil {
		t.Fatal("bootstrapWithRetry reported a permanently blocked bootstrap as success")
	}

	if !strings.Contains(err.Error(), "bootstrap is not available yet") {
		t.Errorf("the give-up does not quote the node's refusal: %v", err)
	}
}

func TestUpTreatsAnAlreadyBootstrappedNodeAsSuccess(t *testing.T) {
	f := newFixture(t)
	writeTalosconfig(t, f.dir)
	f.rec.failAt = "bootstrap"
	f.rec.err = alreadyBootstrappedError()

	transcript := f.mustRun(t)

	wants(t, transcript, "[ 8/10] bootstrap", "already bootstrapped")

	for _, op := range []string{"kubeconfig", "waitNodeReady", "installStorage"} {
		if !f.rec.did(op) {
			t.Errorf("%s never ran after a node reported it was already bootstrapped\n"+
				"  reason: that refusal is the node agreeing etcd exists, which is the whole precondition of the steps after it", op)
		}
	}
}

// The near-miss mutants, and the reason the matcher is a gRPC CODE rather than
// a string: everything else from bootstrap is a real failure, and swallowing it
// would leave `up` waiting on a node that can never become Ready.
func TestUpFailsOnABootstrapErrorThatIsNotAlreadyBootstrapped(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{
			// The node's OTHER refusal: apid is up but the runtime is not ready
			// to bootstrap yet. RETRYING IS THE ANSWER, and it has already
			// happened by the time an error reaches this layer —
			// bootstrapWithRetry sits inside the hook and spends its whole
			// budget on exactly this code. One arriving HERE is therefore a
			// precondition that never cleared, which is a real failure: Up must
			// not treat it as success and leave step 9 waiting on a node that
			// can never report Ready.
			"another gRPC code",
			fmt.Errorf("bootstrapping etcd: %w",
				status.Error(codes.FailedPrecondition, "bootstrap is not available yet")),
		},
		{
			// The same WORDS with no status attached. A substring matcher would
			// accept this; nothing in Talos produces it over the wire, and
			// anything that did is not a node telling us etcd exists.
			"the same message with no code",
			errors.New("etcd data directory is not empty"),
		},
		{
			"an ordinary failure",
			errors.New("connection refused"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			writeTalosconfig(t, f.dir)
			f.rec.failAt = "bootstrap"
			f.rec.err = tc.err

			err := f.run(t)
			if err == nil {
				t.Fatalf("a failing bootstrap (%v) was reported as a working cluster\n"+
					"  reason: only AlreadyExists means etcd is there; every other error leaves a node that never reaches Ready", tc.err)
			}

			if f.rec.did("kubeconfig") {
				t.Error("the bring-up continued past a bootstrap that failed")
			}
		})
	}
}

// The matcher itself, at the unit it is written in. The message is upstream's
// to reword; the code is what Talos's own API contract carries.
func TestAlreadyBootstrappedMatchesTheGRPCCodeNotTheMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"the node's refusal", status.Error(codes.AlreadyExists, "etcd data directory is not empty"), true},
		{"wrapped, as bootstrapEtcd wraps it", alreadyBootstrappedError(), true},
		{"a different code", status.Error(codes.FailedPrecondition, "bootstrap is not available yet"), false},
		{"the message alone", errors.New("etcd data directory is not empty"), false},
		{"anything else", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := alreadyBootstrapped(tc.err); got != tc.want {
				t.Errorf("alreadyBootstrapped(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ── the kexec workaround is the CALLER's decision, carried faithfully ───────
//
// WHICH hosts need it is a fact about the host, so the gate lives in cmd/tinq
// (see TestUpOptionsDisablesKexecOnAppleSiliconOnly). What this package owes is
// that the answer it is handed is the answer it asks for and the answer it
// announces — a field silently dropped between UpOptions and ConfigInput is a
// node that kexecs into a kernel it cannot boot, with a transcript that says
// nothing at all.

func TestUpLeavesKexecAloneUnlessTheCallerAsks(t *testing.T) {
	f := newFixture(t)
	f.opts.DisableKexec = false

	transcript := f.mustRun(t)

	if f.rec.input.DisableKexec {
		t.Error("kexec was disabled although the caller did not ask\n" +
			"  reason: kexec skips a firmware boot and is FASTER; disabling it where the\n" +
			"  workaround does not apply is a tax paid for another substrate's bug")
	}

	if strings.Contains(transcript, "kexec_load_disabled") {
		t.Errorf("transcript announces a workaround that was not requested\n%s", redact(transcript))
	}
}

// The sysctl must be requested, and the transcript must say so: a bring-up that
// silently changed the node's reboot behaviour is one nobody can account for
// later.
func TestUpDisablesKexecWhenTheCallerAsks(t *testing.T) {
	f := newFixture(t)
	f.opts.DisableKexec = true

	transcript := f.mustRun(t)

	if !f.rec.input.DisableKexec {
		t.Error("kexec was left enabled although the caller asked for it to be disabled\n" +
			"  reason: Talos kexecs into the installed kernel, and under QEMU on macOS that\n" +
			"  path dies in the guest — the node never boots what it just installed")
	}

	wants(t, transcript, "kexec_load_disabled=1", "MAINTENANCE")
}

// "" IS A REAL ANSWER for ConsoleArg, and adopt is the caller that gives it:
// hardware has a firmware-configured console, and this host's architecture says
// nothing about a machine that is not this host. Printed unconditionally the
// line announced a BLANK value, and credited it to "this host's serial" — a
// claim about the wrong machine, made on the one substrate where it is wrong.
func TestStep6SaysNothingAboutAKernelArgItWasNotGiven(t *testing.T) {
	f := newFixture(t)
	f.opts.ConsoleArg = ""

	transcript := f.mustRun(t)

	if strings.Contains(transcript, "extraKernelArgs") {
		t.Errorf("step 6 announced an extraKernelArgs it was never given\n"+
			"  reason: the value is blank, so the line names a setting that is not in "+
			"the config\n%s", redact(transcript))
	}

	if strings.Contains(transcript, "serial goes dead") {
		t.Errorf("step 6 kept the reason for a line it did not print\n"+
			"  reason: a justification with nothing above it reads as a step of its "+
			"own\n%s", redact(transcript))
	}
}

// The argument configures THE NODE. On QEMU the node happens to be a guest of
// this host, which is what made "this host's serial" survive; on hardware the
// node is somewhere else entirely and the credit is simply false.
func TestStep6CreditsTheKernelArgToTheNode(t *testing.T) {
	transcript := newFixture(t).mustRun(t)

	wants(t, transcript, "extraKernelArgs: "+fakeConsoleArg+" (the node's serial console)")

	if strings.Contains(transcript, "this host's serial") {
		t.Errorf("step 6 credits the console arg to THIS host\n"+
			"  reason: adopt drives a node that is not this host, and the transcript "+
			"is what an operator learns Talos from\n%s", redact(transcript))
	}
}

// The two fixture addresses are deliberately UNRELATED to each other and to
// every other value in this file. Both are inside one /24 so CheckNetwork
// accepts them — a same-wire re-pin, which is the only kind that can finish —
// and they differ in the last octet so a hook handed the wrong one cannot pass.
const (
	fakeMaintenanceEndpoint = "10.99.0.186:50000"
	fakeInstalledEndpoint   = "10.99.0.7:50000"
	// The Kubernetes endpoint of the SAME node, at the SAME address. It is not
	// derived from the block — under QEMU it is a forward's host side and could
	// not be — so every static fixture has to state it, and a fixture that left
	// the loopback default in place would be a node whose kubeconfig and
	// control-plane endpoint both point at 127.0.0.1.
	fakeInstalledKubeEndpoint = "https://10.99.0.7:6443"
)

func fakeStaticNetwork() *Network {
	return &Network{
		Address:      "10.99.0.7/24",
		Gateway:      "10.99.0.1",
		Nameservers:  []string{"10.99.0.53"},
		HardwareAddr: "84:47:09:47:35:f9",
	}
}

// THE SEAM, not the function. Everything about the two addresses is correct in
// cluster/network.go and worth nothing if Up hands the wrong one to a hook —
// which compiles, because all five take a string.
func TestUpDialsMaintenanceBeforeTheInstallAndTheStaticAddressAfter(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosEndpoint = fakeMaintenanceEndpoint
	f.opts.KubeEndpoint = fakeInstalledKubeEndpoint
	f.opts.Network = fakeStaticNetwork()

	f.mustRun(t)

	before := []string{"waitMaintenance", "applyConfig"}
	for _, op := range before {
		if got := f.rec.endpoint[op]; got != fakeMaintenanceEndpoint {
			t.Errorf("%s dialled %q, want %q\n"+
				"  reason: before the install the node holds ONLY the maintenance address",
				op, got, fakeMaintenanceEndpoint)
		}
	}

	after := []string{"waitBootstrapReady", "bootstrap", "kubeconfig"}
	for _, op := range after {
		if got := f.rec.endpoint[op]; got != fakeInstalledEndpoint {
			t.Errorf("%s dialled %q, want %q\n"+
				"  reason: the node rebooted into what it installed and stopped holding %s;\n"+
				"  a wait pointed there can only spend its whole budget",
				op, got, fakeInstalledEndpoint, fakeMaintenanceEndpoint)
		}
	}
}

// The certificate names what the client dials, and after the install that is
// the static address. Named wrong, the node installs, boots, serves apid, and
// every authenticated call fails on a certificate nobody can point at.
func TestUpPutsTheStaticAddressInTheCertificate(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosEndpoint = fakeMaintenanceEndpoint
	f.opts.KubeEndpoint = fakeInstalledKubeEndpoint
	f.opts.Network = fakeStaticNetwork()

	f.mustRun(t)

	if got := f.rec.input.APIAddress; got != "10.99.0.7" {
		t.Errorf("APIAddress = %q, want 10.99.0.7\n"+
			"  reason: this becomes apid's subject alt name AND the talosconfig endpoint,\n"+
			"  both baked at generation time and unrepairable afterwards", got)
	}

	// The SAME node, on its other port. This one is not derived — it is the
	// caller's string, carried through — and it lands in the kubeconfig's
	// server and in cluster.controlPlane.endpoint, which is a control plane
	// nobody can reach if it names a host the node does not take.
	if got := f.rec.input.Endpoint; got != fakeInstalledKubeEndpoint {
		t.Errorf("GenerateConfig got Endpoint %q, want %q\n"+
			"  reason: the kubeconfig's server and the control-plane endpoint are both baked\n"+
			"  here, and neither can be repaired after the node has installed",
			got, fakeInstalledKubeEndpoint)
	}

	if f.rec.input.Network == nil {
		t.Error("the network block never reached ConfigInput\n" +
			"  reason: a correct networkOption that nothing calls emits nothing")
	} else if got := f.rec.input.Network.Address; got != "10.99.0.7/24" {
		t.Errorf("ConfigInput.Network.Address = %q, want 10.99.0.7/24", got)
	}
}

// EVERY MACHINE THAT EXISTED BEFORE THIS FEATURE takes this path, including
// every QEMU one. With no block the node does not move, so both halves dial the
// same address and the config carries no network at all.
func TestUpDialsOneAddressForAMachineWithNoNetworkBlock(t *testing.T) {
	f := newFixture(t)

	f.mustRun(t)

	// A FLOOR, because the loop below asserts NOTHING against an empty map —
	// and this test is the designated regression guard for every machine that
	// existed before this feature. The five are the hooks that take an
	// endpoint: waitMaintenance, applyConfig, waitBootstrapReady, bootstrap
	// and kubeconfig.
	if len(f.rec.endpoint) != 5 {
		t.Fatalf("%d operations recorded an endpoint, want 5 (%v)\n"+
			"  reason: a bring-up that dialled nothing would pass the loop below in silence",
			len(f.rec.endpoint), f.rec.endpoint)
	}

	for op, got := range f.rec.endpoint {
		if got != f.opts.TalosEndpoint {
			t.Errorf("%s dialled %q, want %q — a DHCP node does not move",
				op, got, f.opts.TalosEndpoint)
		}
	}

	if f.rec.input.Network != nil {
		t.Error("ConfigInput.Network is set for a machine with no network block")
	}
}

// Refused where the two endpoint refusals already are: BEFORE Boot. Failing
// here costs nothing; failing after costs a VM nobody asked to keep and, on
// hardware, a node that has already been told to install.
func TestUpRefusesAnUnreachableStaticAddressBeforeBooting(t *testing.T) {
	f := newFixture(t)
	f.opts.TalosEndpoint = "192.168.1.186:50000"
	f.opts.Network = fakeStaticNetwork() // 10.99.0.7/24 — another segment entirely

	err := f.run(t)
	if err == nil {
		t.Fatal("Up accepted a static address on a different segment than the node it is adopting")
	}

	if f.booted != 0 {
		t.Error("Up booted the machine before refusing\n" +
			"  reason: the refusal is provable from the options alone, and reaching it later\n" +
			"  leaves residue for a verdict that was free")
	}

	if !strings.Contains(err.Error(), "10.99.0.7/24") {
		t.Errorf("the refusal does not name the address that caused it: %s", err)
	}
}

// THE FOURTH ADDRESS, and the one nothing derives. KubeEndpoint stays a field
// because under QEMU it is the host side of a forward and cannot be computed
// from anything here — but a machine with a static block DOES know where the
// node answers afterwards, and this string is written into the kubeconfig's
// server AND into cluster.controlPlane.endpoint. Naming a host the node never
// takes installs a control plane nobody can reach, and neither artifact can be
// regenerated once the node has left maintenance mode.
func TestUpRefusesAKubeEndpointTheStaticNodeWillNotAnswerAt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		wantMsg  []string
	}{
		{
			// The fixture's own loopback, which is right for a QEMU forward and
			// is a control plane pointed at nothing on a machine that moves.
			"another host entirely", "https://127.0.0.1:6443",
			[]string{"127.0.0.1", "10.99.0.7", "https://10.99.0.7:6443"},
		},
		{
			// The scheme omitted. It reaches the kubeconfig's server verbatim,
			// where it is not a URL at all.
			"not a URL", "10.99.0.7:6443",
			[]string{"is not a URL with a host"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.opts.TalosEndpoint = fakeMaintenanceEndpoint
			f.opts.KubeEndpoint = tc.endpoint
			f.opts.Network = fakeStaticNetwork()

			err := f.run(t)
			if err == nil {
				t.Fatal("Up accepted a Kubernetes endpoint naming an address this node never holds\n" +
					"  reason: the kubeconfig's server and cluster.controlPlane.endpoint are both\n" +
					"  baked at generation time, and an installed node cannot be reconfigured")
			}

			// BEFORE Boot, beside the three refusals that are already there.
			// On hardware, reaching this later spends a node that has been told
			// to install.
			if f.booted != 0 {
				t.Errorf("the machine was booted %d times before the endpoint was checked\n"+
					"  reason: the verdict is provable from the options alone, and failing here costs nothing",
					f.booted)
			}

			if f.rec.did("generateConfig") {
				t.Error("a config was generated with an endpoint the node cannot answer at")
			}

			for _, want := range tc.wantMsg {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not contain %q, so it cannot be acted on:\n%s", want, redactErr(err))
				}
			}
		})
	}
}

// The other side of the gate: a machine with NO static block keeps today's
// behaviour exactly. Every QEMU bring-up is here, and its KubeEndpoint is the
// host side of a forward — an address the node itself never holds, on purpose.
func TestUpDoesNotCheckTheKubeEndpointOfAMachineWithNoNetworkBlock(t *testing.T) {
	f := newFixture(t)
	// A forward on the host, to a node that answers at neither address.
	f.opts.TalosEndpoint = "127.0.0.1:50000"
	f.opts.KubeEndpoint = "https://127.0.0.1:6443"

	f.mustRun(t)

	if got := f.rec.input.Endpoint; got != "https://127.0.0.1:6443" {
		t.Errorf("GenerateConfig got Endpoint %q, want the caller's forward untouched\n"+
			"  reason: with no static block nothing here knows where the node is reached from,\n"+
			"  and a forward's host side is SUPPOSED to be an address the node does not hold", got)
	}
}

// A CLAIM ABOUT REALITY, printed only when it is one. On a segment with no DHCP
// the operator typed the node's FINAL address at the GRUB prompt, so it is
// adopted and answers at the same place — and a transcript announcing a move
// that is not happening sends the operator looking for a node at an address
// nothing changed to.
func TestStep6AnnouncesTheMoveOnlyWhenTheNodeMoves(t *testing.T) {
	moves := newFixture(t)
	moves.opts.TalosEndpoint = fakeMaintenanceEndpoint
	moves.opts.KubeEndpoint = fakeInstalledKubeEndpoint
	moves.opts.Network = fakeStaticNetwork()

	wants(t, moves.mustRun(t),
		"network: 10.99.0.7/24 via 10.99.0.1 on 84:47:09:47:35:f9, dhcp off",
		"this node MOVES: adopted at "+fakeMaintenanceEndpoint+
			", answers at "+fakeInstalledEndpoint+" from the reboot onward")

	// Adopted at the address the static block already names.
	stays := newFixture(t)
	stays.opts.TalosEndpoint = fakeInstalledEndpoint
	stays.opts.KubeEndpoint = fakeInstalledKubeEndpoint
	stays.opts.Network = fakeStaticNetwork()

	transcript := stays.mustRun(t)

	wants(t, transcript, "network: 10.99.0.7/24 via 10.99.0.1 on 84:47:09:47:35:f9, dhcp off")

	if strings.Contains(transcript, "this node MOVES") {
		t.Errorf("step 6 announces a move for a node adopted at its own static address\n%s",
			redact(transcript))
	}
}

// ── the mirror list is carried, not interpreted ─────────────────────────────
//
// WHERE a mirror lives is the caller's knowledge (a QEMU host alias, a LAN
// address), and WHETHER anything answers there is not knowable from here at
// all. What this package owes is that the list it is handed is the list it
// asks for — a field dropped between UpOptions and ConfigInput is a node that
// pulls every public image from the internet perfectly well, and fails only on
// the one image that exists nowhere but the mirror.

func TestUpCarriesTheRegistryMirrorsToConfig(t *testing.T) {
	f := newFixture(t)
	f.opts.Registries = []RegistryMirror{{
		Host:     "10.0.2.2:5000",
		Endpoint: "http://10.0.2.2:5000",
	}}

	f.mustRun(t)

	if !reflect.DeepEqual(f.rec.input.Registries, f.opts.Registries) {
		t.Errorf("ConfigInput.Registries = %+v, want %+v\n"+
			"  reason: dropped here the node still pulls every public image, so nothing\n"+
			"  downstream notices until an image that exists ONLY on the mirror is deployed",
			f.rec.input.Registries, f.opts.Registries)
	}
}

func TestUpAsksForNoMirrorsWhenTheCallerNamedNone(t *testing.T) {
	f := newFixture(t)

	f.mustRun(t)

	if f.rec.input.Registries != nil {
		t.Errorf("ConfigInput.Registries = %+v, want nil — a mirror nobody asked for is an\n"+
			"  endpoint nothing is listening on, and every image pull then waits it out",
			f.rec.input.Registries)
	}
}

// fakeJoin is the cluster a joining fixture is pointed at. The values are
// deliberately distinguishable from the fixture's own KubeEndpoint and from
// fakeKubeconfig, because most of what these tests assert is that the JOINED
// cluster's values were used and not the joining machine's.
const (
	fakeJoinSecrets    = "cluster: {id: joined}\n"
	fakeJoinEndpoint   = "https://10.9.9.1:6443"
	fakeJoinKubeconfig = "apiVersion: v1\nkind: Config\n# the joined cluster's\n"
)

func joining(f *upFixture) {
	f.opts.Join = &JoinOptions{
		SecretsBundle:   []byte(fakeJoinSecrets),
		ClusterEndpoint: fakeJoinEndpoint,
		Kubeconfig:      []byte(fakeJoinKubeconfig),
	}
}

// THE ONE THAT MATTERS. A joining node's etcd data directory is empty, so it
// does not refuse a bootstrap the way an already-bootstrapped node does -- it
// accepts, and forms a second cluster carrying the first one's PKI. Both then
// look healthy and the two nodes never see each other, so nothing downstream
// can detect this: the assertion has to live here.
func TestJoinNeverBootstraps(t *testing.T) {
	f := newFixture(t)
	joining(f)

	transcript := f.mustRun(t)

	for _, called := range f.rec.called {
		if called == "bootstrap" {
			t.Fatalf("a joining node called bootstrap\n"+
				"  reason: its etcd is empty, so the call SUCCEEDS and splits the cluster in two "+
				"-- both halves answer, both look healthy, and the nodes never see each other\n%s",
				redact(transcript))
		}
	}

	wants(t, transcript, "skipped (joining an existing cluster)")
}

// The bundle is the join. Generating against a fresh one produces a node whose
// certificates are signed by a CA its peers do not trust, which presents as a
// node that installs perfectly and then never appears in the cluster.
func TestJoinGeneratesAgainstTheExistingSecretsBundle(t *testing.T) {
	f := newFixture(t)
	joining(f)

	f.mustRun(t)

	if got := string(f.rec.input.SecretsBundle); got != fakeJoinSecrets {
		t.Errorf("the config was generated against %q, not the joined cluster's secrets bundle\n"+
			"  reason: a fresh bundle means fresh CAs, and the cluster rejects the node as untrusted\n"+
			"  want: %q", got, fakeJoinSecrets)
	}
}

// Two addresses that must NOT be collapsed: the cluster's API endpoint, and
// this node's own address. Pointing a joining node's endpoint at itself makes
// it look for a control plane that does not exist until it has already joined.
func TestJoinPointsTheEndpointAtTheClusterAndTheCertificateAtTheNode(t *testing.T) {
	f := newFixture(t)
	joining(f)

	f.mustRun(t)

	if got := f.rec.input.Endpoint; got != fakeJoinEndpoint {
		t.Errorf("cluster endpoint is %q, not the joined cluster's %q\n"+
			"  reason: KubeEndpoint describes the machine being brought up, which is right "+
			"for the node that IS the cluster and wrong for every node added after it",
			got, fakeJoinEndpoint)
	}

	if got := f.rec.input.APIAddress; got == fakeJoinEndpoint {
		t.Errorf("APIAddress was set to the cluster endpoint %q\n"+
			"  reason: it is the apid certificate's subject alt name and the talosconfig's "+
			"endpoint, so it must name THIS node or nothing can dial it directly", got)
	}
}

// A join issues no new admin credential. Minting one would succeed -- same CA
// -- and leave two valid, indistinguishable kubeconfigs for one cluster.
func TestJoinReusesTheClustersKubeconfigRatherThanMintingOne(t *testing.T) {
	f := newFixture(t)
	joining(f)

	f.mustRun(t)

	for _, called := range f.rec.called {
		if called == "kubeconfig" {
			t.Errorf("a joining node asked the node for a kubeconfig\n" +
				"  reason: the cluster already has one; a second is valid, confusing, and " +
				"rendered against whatever this node believes the endpoint to be")
		}
	}

	written, err := os.ReadFile(filepath.Join(f.dir, "kubeconfig"))
	if err != nil {
		t.Fatalf("no kubeconfig in the state dir: %v", err)
	}

	if string(written) != fakeJoinKubeconfig {
		t.Errorf("state dir kubeconfig is not the joined cluster's\n  got:  %q\n  want: %q",
			written, fakeJoinKubeconfig)
	}
}

// "every node is Ready" is satisfied by the cluster's EXISTING nodes, so a join
// must wait on the address it just installed or it reports success for a node
// that has not registered.
func TestJoinWaitsForTheJoiningNodeSpecifically(t *testing.T) {
	f := newFixture(t)
	joining(f)

	f.mustRun(t)

	var sawScoped bool

	for _, called := range f.rec.called {
		if called == "waitNodeReady" {
			t.Errorf("a joining node used the every-node-is-Ready wait\n" +
				"  reason: the existing control plane is already Ready, so it returns before " +
				"the joining node has registered at all")
		}

		if called == "waitNodeReadyAt" {
			sawScoped = true
		}
	}

	if !sawScoped {
		t.Fatal("a joining node never waited for itself to be Ready")
	}
}

// A StorageClass is cluster-scoped and the first node installed it.
func TestJoinDoesNotReinstallClusterStorage(t *testing.T) {
	f := newFixture(t)
	joining(f)

	transcript := f.mustRun(t)

	for _, called := range f.rec.called {
		if called == "installStorage" {
			t.Errorf("a joining node reinstalled the cluster's storage\n" +
				"  reason: the StorageClass is cluster-scoped and already exists; re-applying " +
				"it can re-point the default class at this machine")
		}
	}

	wants(t, transcript, "skipped (the cluster this node joined owns its StorageClass)")
}

// A machine with no Join block must behave exactly as it did before this
// feature existed -- the regression guard for every test above.
func TestWithoutJoinTheBringUpStillBootstrapsAndMintsAKubeconfig(t *testing.T) {
	f := newFixture(t)

	f.mustRun(t)

	var bootstrapped, minted bool

	for _, called := range f.rec.called {
		switch called {
		case "bootstrap":
			bootstrapped = true
		case "kubeconfig":
			minted = true
		}
	}

	if !bootstrapped || !minted {
		t.Errorf("a non-joining bring-up changed shape: bootstrapped=%v mintedKubeconfig=%v\n"+
			"  reason: Join is nil by default and must leave the create path untouched",
			bootstrapped, minted)
	}

	if f.rec.input.SecretsBundle != nil {
		t.Error("a non-joining bring-up was handed a secrets bundle\n" +
			"  reason: it must mint its own, or every cluster shares one PKI")
	}
}
