package qemu

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coglative/talos-in-qemu/cluster"
	"github.com/coglative/talos-in-qemu/driverkit"
	"github.com/coglative/talos-in-qemu/platform"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

// Detect must stay INSIDE create, never hoisted to main: on a host with no
// usable accelerator Detect fails, and teardown of an already-created VM must
// still work. Destroy touching it would make cleanup require a working
// hypervisor — the one thing that must never need one.
func TestDestroyDoesNotProbeThePlatform(t *testing.T) {
	h := &hvf{
		stateRoot: t.TempDir(),
		imageRoot: t.TempDir(),
		detect: func() (*platform.Platform, error) {
			t.Error("Destroy must not probe the host platform")
			return nil, fmt.Errorf("no accelerator on this host")
		},
	}
	m := &unstructured.Unstructured{Object: map[string]interface{}{}}
	m.SetUID("bootstrap-default-gone")
	if err := h.Destroy(context.Background(), m); err != nil {
		t.Fatalf("Destroy of an absent machine must succeed: %v", err)
	}
}

// specFromYAML decodes through the SAME path standalone() uses. That routing is
// the entire point: sigs.k8s.io/yaml goes via JSON, so `cpu: 4` arrives as
// float64. A hand-built map[string]interface{}{"cpu": int64(4)} would pass
// against the old broken .(int64) assertion and prove nothing.
func specFromYAML(t *testing.T, doc string) map[string]interface{} {
	t.Helper()
	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	spec, _, _ := unstructured.NestedMap(obj, "spec")
	return spec
}

func TestSpecCPU(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want int
	}{
		{"explicit", "spec:\n  cpu: 4\n", 4},
		{"absent", "spec:\n  memory: 2Gi\n", 2},
		{"zero", "spec:\n  cpu: 0\n", 2},
		{"non-numeric", "spec:\n  cpu: lots\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := specCPU(specFromYAML(t, tc.doc)); got != tc.want {
				t.Errorf("specCPU = %d, want %d", got, tc.want)
			}
		})
	}
	// The comment on toInt claims int64 is "what the API server path needs":
	// unstructured values from a real client are int64, not the float64 the
	// YAML decoder produces. Nothing above reaches that case, so it is pinned
	// directly — the two arms of toInt must BOTH work or one caller breaks.
	if got := specCPU(map[string]interface{}{"cpu": int64(4)}); got != 4 {
		t.Errorf("specCPU(int64(4)) = %d, want 4 (the API-server path)", got)
	}
}

// dataDisk is OPTIONAL and its absence is load-bearing: an unset field must
// produce exactly the machine this tool produced before the field existed. ""
// is the signal for "no second disk", so the empty string and the absent key
// have to arrive here as the same thing.
func TestSpecDataDisk(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want string
	}{
		{"set", "spec:\n  dataDisk: 40Gi\n", "40Gi"},
		{"absent", "spec:\n  disk: 20Gi\n", ""},
		{"empty", "spec:\n  dataDisk: \"\"\n", ""},
		// spec.disk must not leak into spec.dataDisk: reading the wrong key
		// would give every single-disk machine a second disk.
		{"disk-only-is-not-a-data-disk", "spec:\n  disk: 20Gi\n  cpu: 4\n", ""},
		// -apply reads this YAML with NO API server in front of it, so the
		// CRD's `type: string` never validates. `dataDisk: 40` (unit omitted)
		// decodes as float64 and must read as "not set" — never a panic, and
		// never a silently coerced 40-byte disk.
		{"unquoted-number-is-not-a-size", "spec:\n  dataDisk: 40\n", ""},
		{"bool-is-not-a-size", "spec:\n  dataDisk: true\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := specDataDisk(specFromYAML(t, tc.doc)); got != tc.want {
				t.Errorf("specDataDisk = %q, want %q", got, tc.want)
			}
		})
	}
}

// machineFromYAML builds the *unstructured.Unstructured the readers take from a
// whole CR document, the way readMachine does off disk.
func machineFromYAML(t *testing.T, doc string) *unstructured.Unstructured {
	t.Helper()
	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &unstructured.Unstructured{Object: obj}
}

// A patch is a YAML block-scalar STRING — the same shape talosctl --config-patch
// and talhelper take, and what the CRD schema declares. Two of them read back in
// order, content intact.
func TestConfigPatchesReadsBlockScalarStrings(t *testing.T) {
	doc := "apiVersion: machine.hvf.fleet.io/v1alpha1\n" +
		"kind: TalosMachine\n" +
		"metadata:\n  name: dev\n" +
		"spec:\n" +
		"  configPatches:\n" +
		"    - |\n" +
		"      machine:\n" +
		"        network:\n" +
		"          nameservers:\n" +
		"            - 192.168.122.10\n" +
		"    - |\n" +
		"      machine:\n" +
		"        time:\n" +
		"          servers: [seed.lab]\n"

	patches, err := configPatches(machineFromYAML(t, doc))
	if err != nil {
		t.Fatalf("configPatches: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("got %d patches, want 2", len(patches))
	}
	if !strings.Contains(patches[0], "192.168.122.10") {
		t.Errorf("first patch lost its content\n  got: %q", patches[0])
	}
	if !strings.Contains(patches[1], "seed.lab") {
		t.Errorf("second patch lost its content\n  got: %q", patches[1])
	}
}

// An inline mapping is refused with guidance, not silently coerced: the CRD
// declares items as strings and the convention is a block scalar, so a bare
// mapping is a mistake worth naming at read time rather than a shape to guess at.
func TestConfigPatchesRejectsANonString(t *testing.T) {
	doc := "spec:\n" +
		"  configPatches:\n" +
		"    - machine:\n" +
		"        time:\n" +
		"          servers: [seed.lab]\n"

	if _, err := configPatches(machineFromYAML(t, doc)); err == nil {
		t.Error("a non-string configPatches entry was accepted\n" +
			"  reason: patches are block-scalar strings (talosctl/talhelper convention,\n" +
			"  and what the CRD schema allows); an inline mapping must be named as a\n" +
			"  mistake, not silently reshaped")
	}
}

// Absent is nil, the load-bearing default: a machine that sets no patch must
// produce exactly the config it produced before the field existed.
func TestConfigPatchesAbsentIsNil(t *testing.T) {
	patches, err := configPatches(machineFromYAML(t, "spec:\n  cpu: 2\n"))
	if err != nil {
		t.Fatalf("configPatches: %v", err)
	}
	if patches != nil {
		t.Errorf("absent spec.configPatches must be nil, got %#v", patches)
	}
}

const (
	// The real x86_64 edk2 vars template size, and the size the padding version
	// of this tool wrote. On x86_64 the poisoned file is what makes QEMU refuse
	// to start with "combined size of system firmware exceeds 8388608 bytes".
	x86VarsSize  = 540672
	poisonedSize = 64 << 20
)

// writeSized writes a file of exactly n bytes whose content is identifiable, so
// a test can tell "left alone" from "rewritten to something the same size".
func writeSized(t *testing.T, path string, n int64, fill byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte{fill}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, n); err != nil {
		t.Fatal(err)
	}
}

// The efivars size-heal is the fix this branch shipped without a test, and it
// has to be right in BOTH directions: heal a poisoned file, and never touch a
// good one. Regenerating unconditionally would silently discard the guest's own
// UEFI boot entries, which is real state and does not come back.
func TestEnsureEFIVars(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, path string)
		rewrite bool
	}{
		{"absent", func(*testing.T, string) {}, true},
		{"poisoned-64MiB", func(t *testing.T, p string) {
			writeSized(t, p, poisonedSize, 'P')
		}, true},
		{"matching-size", func(t *testing.T, p string) {
			writeSized(t, p, x86VarsSize, 'G')
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tmpl := filepath.Join(dir, "OVMF_VARS.fd")
			writeSized(t, tmpl, x86VarsSize, 'T')
			vars := filepath.Join(dir, "efivars.fd")
			tc.setup(t, vars)

			if err := ensureEFIVars(vars, tmpl); err != nil {
				t.Fatalf("ensureEFIVars: %v", err)
			}
			st, err := os.Stat(vars)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if st.Size() != x86VarsSize {
				t.Errorf("size = %d, want the template's %d", st.Size(), x86VarsSize)
			}
			// First byte identifies the SOURCE: 'T' means it came from the
			// template, anything else means the pre-existing file survived.
			b := make([]byte, 1)
			f, err := os.Open(vars)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Read(b); err != nil {
				t.Fatal(err)
			}
			if tc.rewrite && b[0] != 'T' {
				t.Errorf("file was not regenerated from the template (first byte %q)", b[0])
			}
			if !tc.rewrite && b[0] != 'G' {
				t.Errorf("a same-size file must be left ALONE — the guest's UEFI "+
					"boot entries live in it; first byte %q", b[0])
			}
		})
	}
}

// requireQEMUImg skips rather than fails: qemu-img is a hard runtime dependency
// of this tool, but a reviewer reading the code on a box without QEMU should not
// see a red suite. Everything it gates is exercised on a host that has it.
func requireQEMUImg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not on PATH")
	}
}

// qcow2VirtualSize reads the virtual size straight out of the qcow2 header
// (magic "QFI\xfb", then big-endian size at offset 24) instead of parsing
// `qemu-img info` prose. The header is a format contract; the prose is not.
func qcow2VirtualSize(t *testing.T, path string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 32 || string(b[:4]) != "QFI\xfb" {
		t.Fatalf("%s is not a qcow2 image", path)
	}
	return binary.BigEndian.Uint64(b[24:32])
}

// The disk is created ONCE and then never touched again. That is not an
// optimisation: system.qcow2 holds the installed OS and data.qcow2 holds the
// user's PVCs, so a re-create that truncated either would silently destroy a
// running machine on the next reconcile tick — and create() runs on EVERY tick
// where Observe reports absent.
func TestEnsureQcow2(t *testing.T) {
	t.Run("creates-at-the-requested-size", func(t *testing.T) {
		requireQEMUImg(t)
		path := filepath.Join(t.TempDir(), "data.qcow2")
		// Kubernetes says 64Mi, qemu-img says 64M and rejects the "i"
		// outright ("Invalid image size specified!"), so the suffix has to be
		// trimmed — and both spellings mean the same power-of-two bytes, so
		// trimming is exact rather than a rounding.
		if err := ensureQcow2(path, "64Mi"); err != nil {
			t.Fatalf("ensureQcow2: %v", err)
		}
		if got, want := qcow2VirtualSize(t, path), uint64(64<<20); got != want {
			t.Errorf("virtual size = %d, want %d", got, want)
		}
	})

	t.Run("reports-a-qemu-img-failure", func(t *testing.T) {
		requireQEMUImg(t)
		path := filepath.Join(t.TempDir(), "data.qcow2")
		// qemu-img is a trust boundary: it is where a malformed spec.disk
		// lands. Swallowing its exit status would launch the VM against a disk
		// that was never created, and the failure would surface as an
		// unexplained qemu error instead of the bad quantity that caused it.
		err := ensureQcow2(path, "banana")
		if err == nil {
			t.Fatal("a rejected image size must be an error")
		}
		if !strings.Contains(err.Error(), "qemu-img") {
			t.Errorf("error must name qemu-img, got: %v", err)
		}
	})

	t.Run("leaves-an-existing-image-alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "system.qcow2")
		// Deliberately NOT a valid qcow2: if the guard is removed, qemu-img
		// overwrites this and the content check fails. No qemu-img needed for
		// the branch that must not reach it.
		if err := os.WriteFile(path, []byte("the installed OS"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureQcow2(path, "64Mi"); err != nil {
			t.Fatalf("ensureQcow2: %v", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "the installed OS" {
			t.Errorf("an existing disk was rewritten (%q) — that is the installed "+
				"system, or the user's PVCs, gone", b)
		}
	})

	t.Run("reports-a-non-ENOENT-stat-error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: an unreadable directory is still readable")
		}
		dir := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		// t.TempDir's cleanup has to be able to descend into it again.
		t.Cleanup(func() { os.Chmod(dir, 0o755) })
		// EACCES is not "already there". Reading it as such skips creation and
		// then launches QEMU against a disk that was never made, surfacing as
		// an unexplained qemu error instead of the permission problem.
		if err := ensureQcow2(filepath.Join(dir, "data.qcow2"), "64Mi"); err == nil {
			t.Fatal("an unreadable parent directory must be an error, not a silent skip")
		}
	})
}

// fakeQEMU stands in for the hypervisor so the ARG LIST — which is the real
// product of create() — can be asserted without booting anything. It records
// its argv one arg per line and honours the pidfile contract create() reads
// back, so create() completes exactly as it would against qemu.
func fakeQEMU(t *testing.T, dir string) (bin string, argv func() []string) {
	t.Helper()
	bin = filepath.Join(dir, "fake-qemu")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$0.args\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  if [ \"$1\" = -pidfile ]; then echo 4242 > \"$2\"; fi\n" +
		"  shift\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, func() []string {
		b, err := os.ReadFile(bin + ".args")
		if err != nil {
			t.Fatalf("fake qemu recorded no args: %v", err)
		}
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
}

const machineDoc = `apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata:
  name: cp0
  namespace: default
spec:
  site: testsite
  role: talos-cp
  image: talos.iso
  cpu: 4
  memory: 2Gi
  disk: 64Mi
  hostForwards:
    - hostPort: 50000
      guestPort: 50000
`

// The qemu argv is asserted WHOLE, position by position, not by substring.
// Order is semantics here — bootindex decides the install lifecycle, and a
// -device that drifts away from the -drive it names is a machine that does not
// start. A Contains-based test passes happily through both mistakes.
//
// The no-dataDisk case is the branch's hard constraint: it must be exactly the
// argv this tool emitted before dataDisk existed, plus serial= and nothing else.
func TestCreateQEMUArgs(t *testing.T) {
	requireQEMUImg(t)
	for _, tc := range []struct {
		name, doc string
		dataDisk  bool
		sysSize   uint64
	}{
		{"without-dataDisk", machineDoc, false, 64 << 20},
		{"with-dataDisk", machineDoc + "  dataDisk: 32Mi\n", true, 64 << 20},
		// The CRD marks spec.disk required, but -apply reads a file with NO
		// API server in front of it, so nothing validates that schema on the
		// bootstrap path. The default is reachable, therefore it is pinned.
		{"disk-unset-falls-back-to-16Gi", strings.Replace(machineDoc, "  disk: 64Mi\n", "", 1), false, 16 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, imageRoot := t.TempDir(), t.TempDir()
			fw := t.TempDir()
			code := filepath.Join(fw, "OVMF_CODE.fd")
			vars := filepath.Join(fw, "OVMF_VARS.fd")
			writeSized(t, code, 1024, 'C')
			writeSized(t, vars, x86VarsSize, 'T')
			image := filepath.Join(imageRoot, "talos.iso")
			writeSized(t, image, 4096, 'I')
			bin, argv := fakeQEMU(t, fw)

			h := &hvf{
				stateRoot: root,
				imageRoot: imageRoot,
				detect: func() (*platform.Platform, error) {
					return &platform.Platform{
						QEMUBinary: bin, Machine: "q35", Accel: "kvm", CPU: "host",
						FirmwareCode: code, FirmwareVars: vars,
						ConsoleArg: "console=ttyS0", ImageArch: "amd64",
					}, nil
				},
			}
			var obj map[string]interface{}
			if err := yaml.Unmarshal([]byte(tc.doc), &obj); err != nil {
				t.Fatal(err)
			}
			m := &unstructured.Unstructured{Object: obj}
			m.SetUID("bootstrap-default-cp0")
			dir := h.dir(m)

			pid, err := h.create(m, dir)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if pid != 4242 {
				t.Errorf("pid = %d, want the 4242 the fake wrote to -pidfile", pid)
			}

			want := []string{
				"-machine", "q35,accel=kvm", "-cpu", "host",
				"-smp", "4",
				"-m", "2048",
				"-drive", "if=pflash,format=raw,readonly=on,file=" + code,
				"-drive", "if=pflash,format=raw,file=" + filepath.Join(dir, "efivars.fd"),
				"-drive", "if=none,id=sys,format=qcow2,file=" + filepath.Join(dir, "system.qcow2"),
				"-device", "virtio-blk-pci,drive=sys,serial=talos-system,bootindex=0",
				"-drive", "if=none,id=cd,media=cdrom,file=" + image,
				"-device", "virtio-blk-pci,drive=cd,bootindex=1",
				"-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:50000-:50000",
				"-device", "virtio-net-pci,netdev=n0",
				// Without this the guest can sit at "executing /sbin/init"
				// past the maintenance budget waiting on the CRNG. Asserted
				// because it is invisible until a bring-up fails as a hang.
				"-device", "virtio-rng-pci",
				"-display", "none",
				"-serial", "file:" + filepath.Join(dir, "serial.log"),
				"-pidfile", filepath.Join(dir, "qemu.pid"),
				"-daemonize",
			}
			dataPath := filepath.Join(dir, "data.qcow2")
			if tc.dataDisk {
				want = append(want,
					"-drive", "if=none,id=data,format=qcow2,file="+dataPath,
					"-device", "virtio-blk-pci,drive=data,serial=talos-data")
			}

			got := argv()
			if len(got) != len(want) {
				t.Fatalf("argv has %d args, want %d\n got: %q\nwant: %q", len(got), len(want), got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
				}
			}

			// The data disk must never be a BOOT CANDIDATE. Firmware walks
			// every bootindex it is given; hand one to the PVC disk and a
			// blank-disk machine can try to boot the wrong device — and the
			// install-loop halt this repo already documents is exactly what a
			// boot-order mistake looks like from the console.
			for _, a := range got {
				if strings.Contains(a, "drive=data") && strings.Contains(a, "bootindex") {
					t.Errorf("the data disk carries a bootindex (%q) — it must never "+
						"be a boot candidate", a)
				}
			}

			// Each disk must be sized from ITS OWN spec field. The sizes never
			// reach the argv, so nothing above would notice the two being
			// crossed — and a data disk silently sized from spec.disk is a
			// StorageClass that runs out of room for no visible reason.
			if got := qcow2VirtualSize(t, filepath.Join(dir, "system.qcow2")); got != tc.sysSize {
				t.Errorf("system.qcow2 virtual size = %d, want %d (spec.disk)", got, tc.sysSize)
			}
			if _, err := os.Stat(dataPath); tc.dataDisk != (err == nil) {
				t.Errorf("data.qcow2 present=%v, want %v", err == nil, tc.dataDisk)
			} else if err == nil {
				if got, want := qcow2VirtualSize(t, dataPath), uint64(32<<20); got != want {
					t.Errorf("data.qcow2 virtual size = %d, want %d (spec.dataDisk)", got, want)
				}
			}
		})
	}
}

// ── -up wiring ──────────────────────────────────────────────────────────────
//
// Everything below tests the TRANSLATION from a CR to cluster.UpOptions. The
// bring-up itself needs a VM and belongs to cluster's own suite; what is
// main.go's alone is the disk serials, the qemu forwards and the profile
// resolution — each of which is a value that would compile just as happily
// wrong.

// Both endpoints are the HOST side of a qemu user-mode forward. A machine that
// forwards neither is not slow to bring up, it is impossible: nothing on the
// host can reach the guest without a bridge.
func TestHostForwardEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name             string
		doc              string
		talos, kubernets string
	}{
		{"both", machineDoc + "    - hostPort: 6443\n      guestPort: 6443\n",
			"127.0.0.1:50000", "https://127.0.0.1:6443"},
		// The host port need not equal the guest port, and reading the wrong
		// side of the pair is invisible until a wait times out.
		{"remapped", "spec:\n  hostForwards:\n    - hostPort: 51000\n      guestPort: 50000\n" +
			"    - hostPort: 7443\n      guestPort: 6443\n",
			"127.0.0.1:51000", "https://127.0.0.1:7443"},
		{"talos-only", machineDoc, "127.0.0.1:50000", ""},
		{"none", "spec:\n  site: testsite\n", "", ""},
		// A forward to some other service must not be mistaken for either.
		{"unrelated", "spec:\n  hostForwards:\n    - hostPort: 8080\n      guestPort: 80\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]interface{}
			if err := yaml.Unmarshal([]byte(tc.doc), &obj); err != nil {
				t.Fatal(err)
			}
			m := &unstructured.Unstructured{Object: obj}
			if got := talosEndpoint(m); got != tc.talos {
				t.Errorf("talosEndpoint = %q, want %q", got, tc.talos)
			}
			if got := kubeEndpoint(m); got != tc.kubernets {
				t.Errorf("kubeEndpoint = %q, want %q", got, tc.kubernets)
			}
		})
	}
}

// THE TRANSCRIPT IS THE FEATURE, and stderr does not respect it: anything
// logged while -up is running interleaves into the ten steps. The
// extraKernelArgs hint used to be logged by create(), which -up's Boot closure
// calls directly — so every bring-up printed it between steps 3 and 4, where
// step 6 says the same thing better and in the right place.
//
// -apply and the controller stop at a booted VM and still need it, so it moved
// up one level rather than away.
func TestOnlyCreateTheVerbLogsTheKernelArgHint(t *testing.T) {
	requireQEMUImg(t)

	logged := func(t *testing.T, call func(*hvf, *unstructured.Unstructured, string) error) string {
		t.Helper()

		fw := t.TempDir()
		code := filepath.Join(fw, "OVMF_CODE.fd")
		vars := filepath.Join(fw, "OVMF_VARS.fd")
		writeSized(t, code, 1024, 'C')
		writeSized(t, vars, x86VarsSize, 'T')
		imageRoot := t.TempDir()
		writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
		bin, _ := fakeQEMU(t, fw)

		h := &hvf{
			stateRoot: t.TempDir(), imageRoot: imageRoot,
			detect: func() (*platform.Platform, error) {
				return &platform.Platform{
					QEMUBinary: bin, Machine: "q35", Accel: "kvm", CPU: "host",
					FirmwareCode: code, FirmwareVars: vars,
					ConsoleArg: "console=ttyS0", ImageArch: "amd64",
				}, nil
			},
		}

		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(machineDoc), &obj); err != nil {
			t.Fatal(err)
		}
		m := &unstructured.Unstructured{Object: obj}
		m.SetUID("bootstrap-default-cp0")

		var buf strings.Builder

		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		if err := call(h, m, h.dir(m)); err != nil {
			t.Fatalf("create: %v", err)
		}

		return buf.String()
	}

	t.Run("Create-logs-it", func(t *testing.T) {
		out := logged(t, func(h *hvf, m *unstructured.Unstructured, _ string) error {
			return h.Create(context.Background(), m)
		})
		if !strings.Contains(out, "extraKernelArgs: [console=ttyS0]") {
			t.Errorf("-apply no longer prints the console hint: %q\n"+
				"  reason: -apply stops at a booted VM and leaves the operator to write that patch by hand",
				out)
		}
	})

	t.Run("create-does-not", func(t *testing.T) {
		out := logged(t, func(h *hvf, m *unstructured.Unstructured, dir string) error {
			_, err := h.create(m, dir)

			return err
		})
		if out != "" {
			t.Errorf("create() logged %q\n"+
				"  reason: -up's Boot calls create() directly, and anything on stderr interleaves "+
				"into the ten-step transcript that is the whole feature", out)
		}
	})
}

// status.apiEndpoint and the endpoint -up hands cluster.Up are two answers to
// ONE question, and until this test nothing held them together: Observe scanned
// spec.hostForwards itself, with its own literal 50000 and its own
// "127.0.0.1:%d". Two copies of one rule drift, and the copy was already wrong
// — a forward with the right guestPort and no hostPort came back as
// "127.0.0.1:0", an address published as status that can never answer.
func TestObserveReportsTheSameEndpointUpUses(t *testing.T) {
	for _, tc := range []struct {
		name, forwards, want string
	}{
		{"default", "    - hostPort: 50000\n      guestPort: 50000\n", "127.0.0.1:50000"},
		// The host port need not equal the guest port.
		{"remapped", "    - hostPort: 51000\n      guestPort: 50000\n", "127.0.0.1:51000"},
		{"unrelated-forward-only", "    - hostPort: 8080\n      guestPort: 80\n", ""},
		// Port 0 is not an endpoint. An entry naming the guest port with no
		// hostPort forwards nothing at all.
		{"guest-port-with-no-host-port", "    - guestPort: 50000\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imageRoot := t.TempDir()
			writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
			h := &hvf{
				stateRoot: t.TempDir(), imageRoot: imageRoot,
				detect: func() (*platform.Platform, error) { return &platform.Platform{}, nil },
			}

			doc := strings.Split(machineDoc, "  hostForwards:")[0] + "  hostForwards:\n" + tc.forwards

			var obj map[string]interface{}
			if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
				t.Fatal(err)
			}
			m := &unstructured.Unstructured{Object: obj}
			m.SetUID("bootstrap-default-cp0")

			// Running demands DISKS and a VERIFIED process, so this needs both
			// or Observe reports Absent and every assertion below passes for
			// the wrong reason. The test binary's own pid no longer qualifies:
			// it does not carry the state dir in its argv, which is exactly
			// what ProcessMatches is for.
			dir := h.dir(m)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "system.qcow2"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			pid := startDecoy(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
				[]byte(fmt.Sprint(pid)), 0o644); err != nil {
				t.Fatal(err)
			}

			state, status, err := h.Observe(context.Background(), m)
			if err != nil || state != driverkit.Running {
				t.Fatalf("Observe = (%v, %v), want a running machine", state, err)
			}

			if got := status["apiEndpoint"]; got != tc.want {
				t.Errorf("Observe apiEndpoint = %q, want %q", got, tc.want)
			}

			// The pin. Both being independently right is not enough: they must
			// be the SAME answer, or `tinq -apply` prints an address `tinq -up`
			// does not use.
			opts, err := upOptions(h, m, driverkit.Running, status)
			if err != nil {
				t.Fatalf("upOptions: %v", err)
			}
			if status["apiEndpoint"] != opts.TalosEndpoint {
				t.Errorf("status.apiEndpoint = %q but -up talks to %q\n"+
					"  reason: one question, two answers — whichever is wrong, the operator is "+
					"debugging against an address nothing is listening on",
					status["apiEndpoint"], opts.TalosEndpoint)
			}
		})
	}
}

// The serial is what the generated config selects the PVC volume on, and it
// must be emitted ONLY when the disk exists — a config asking for a volume on a
// disk that was never attached waits for it forever and the node never reaches
// Ready.
func TestDataDiskSerial(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{"set", "spec:\n  dataDisk: 40Gi\n", DiskSerialData},
		{"absent", "spec:\n  disk: 20Gi\n", ""},
		// The typo that costs an hour: no unit, so this is a float64 and reads
		// as "not set" — in create() AND here, which is the agreement that
		// keeps the two halves of storage consistent.
		{"unquoted-number-is-not-a-size", "spec:\n  dataDisk: 40\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dataDiskSerial(specFromYAML(t, tc.doc)); got != tc.want {
				t.Errorf("dataDiskSerial = %q, want %q", got, tc.want)
			}
		})
	}
}

// writeISO writes the smallest file InspectImageVersion will classify: an
// ISO9660 primary volume descriptor at sector 16 carrying Talos's volume id,
// space-padded as the format requires.
//
// A junk file reads as "", and "" is also what a TalosVersion that was never
// resolved looks like — so a fixture built from one cannot tell the version
// being read from the field being left empty, and that field is what pins the
// installer tag written to the node's disk.
func writeISO(t *testing.T, path, volumeID string) {
	t.Helper()
	const sector = 2048
	iso := make([]byte, 17*sector)
	pvd := iso[16*sector:]
	pvd[0] = 1 // primary, not just any descriptor
	copy(pvd[1:6], "CD001")
	for i := 40; i < 72; i++ {
		pvd[i] = ' '
	}
	copy(pvd[40:72], volumeID)
	if err := os.WriteFile(path, iso, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeHost is what detect resolved. NONE of these values may be the ones this
// test binary's own host would produce, and none of them may be equal to each
// other: step 1's line is four host facts in a fixed order, and four values
// that are all plausible strings is exactly the shape a swap survives.
func fakeHost() *platform.Platform {
	return &platform.Platform{
		OS:         "linux",
		QEMUBinary: "qemu-system-fake",
		Machine:    "q35",
		Accel:      "kvm",
		CPU:        "host",
		ConsoleArg: "console=ttyFAKE0",
		ImageArch:  "amd64",
	}
}

// Every field cluster.Up is handed, asserted without a hypervisor. Each is a
// value that compiles just as happily wrong and is only visibly wrong minutes
// into a bring-up.
func TestUpOptions(t *testing.T) {
	imageRoot := t.TempDir()
	writeISO(t, filepath.Join(imageRoot, "talos.iso"), "TALOS_V1_12_3")
	root := t.TempDir()
	d := &hvf{
		stateRoot: root, imageRoot: imageRoot,
		detect: func() (*platform.Platform, error) { return fakeHost(), nil },
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(machineDoc+
		"    - hostPort: 6443\n      guestPort: 6443\n  dataDisk: 40Gi\n"), &obj); err != nil {
		t.Fatal(err)
	}
	m := &unstructured.Unstructured{Object: obj}
	m.SetUID("bootstrap-default-cp0")

	opts, err := upOptions(d, m, driverkit.Absent, nil)
	if err != nil {
		t.Fatalf("upOptions: %v", err)
	}

	// The state dir is the MACHINE's, not the root: the artifacts have to
	// carry the identity they belong to or -destroy cannot sweep them, and a
	// talosconfig that outlives its cluster is residue with a private key in it.
	if want := filepath.Join(root, "testsite", "bootstrap-default-cp0"); opts.StateDir != want {
		t.Errorf("StateDir = %q, want %q", opts.StateDir, want)
	}
	// The installer tag is pinned to THIS, and it is read from the image rather
	// than defaulted: left unset Talos substitutes the config generator's own
	// version and a fresh install silently becomes a cross-version upgrade.
	if opts.TalosVersion != "v1.12.3" {
		t.Errorf("TalosVersion = %q, want the ISO volume id's v1.12.3\n"+
			"  reason: this is written to the node's disk as the installer tag, and an empty "+
			"one is a version Talos fills in for us", opts.TalosVersion)
	}
	// The version SOURCE names the image, because cluster.Up no longer has the
	// path to name it with — and the name is the only thing in the transcript
	// that says which of several ISOs a bring-up actually read.
	if want := "talos.iso (ISO volume id)"; opts.VersionSource != want {
		t.Errorf("VersionSource = %q, want %q\n"+
			"  reason: step 2 prints this verbatim, and a bring-up that does not name its image "+
			"cannot be told from one that read a different one", opts.VersionSource, want)
	}
	// Step 1's line, and it is assembled HERE because cluster.Up must not know
	// what an accelerator is. Four host facts in a fixed order: swapped, the
	// transcript describes a host that does not exist.
	if want := "linux/amd64, kvm, qemu-system-fake"; opts.Substrate != want {
		t.Errorf("Substrate = %q, want %q", opts.Substrate, want)
	}
	// The console arg is the HOST's, and it is a guest fact only because the
	// README requires the image arch to match. A literal here would read
	// correctly on amd64 and put an arm64 node's console on a UART it has not got.
	if opts.ConsoleArg != "console=ttyFAKE0" {
		t.Errorf("ConsoleArg = %q, want the detected host's console=ttyFAKE0", opts.ConsoleArg)
	}
	if opts.TalosEndpoint != "127.0.0.1:50000" {
		t.Errorf("TalosEndpoint = %q, want 127.0.0.1:50000", opts.TalosEndpoint)
	}
	if opts.KubeEndpoint != "https://127.0.0.1:6443" {
		t.Errorf("KubeEndpoint = %q, want https://127.0.0.1:6443", opts.KubeEndpoint)
	}
	if opts.SystemDisk != (cluster.DiskRef{Serial: DiskSerialSystem}) || opts.DataDiskSerial != DiskSerialData {
		t.Errorf("disks = %v/%q, want serial %q/%q\n"+
			"  reason: swapped, the install target and the PVC volume trade places and the OS lands on the data disk",
			opts.SystemDisk, opts.DataDiskSerial, DiskSerialSystem, DiskSerialData)
	}
	if opts.ClusterName != "cp0" {
		t.Errorf("ClusterName = %q, want the machine's name cp0", opts.ClusterName)
	}
	if opts.Boot == nil {
		t.Fatal("Boot must be supplied; cluster.Up has no fallback for it")
	}
}

// The kexec workaround is a fact about the HOST, so this is where it is decided
// — and both halves of the gate are load-bearing. Each case names the host it
// is about rather than inheriting the one running the tests, which is the only
// way a workaround for someone else's machine is provable from this one.
func TestUpOptionsDisablesKexecOnAppleSiliconOnly(t *testing.T) {
	for _, tc := range []struct {
		os, arch string
		want     bool
		reason   string
	}{
		{"linux", "arm64", false,
			"kexec works under KVM and skips a firmware boot; disabling it there is a tax paid for a macOS bug"},
		{"darwin", "amd64", false,
			"the bug is arm64's — upstream gates on TargetArch == arm64 — so an Intel Mac pays a firmware boot for nothing"},
		{"darwin", "arm64", true,
			"Talos kexecs into the kernel it just installed, and under QEMU on macOS that path dies in the guest on arm64"},
	} {
		t.Run(tc.os+"/"+tc.arch, func(t *testing.T) {
			imageRoot := t.TempDir()
			writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
			d := &hvf{
				stateRoot: t.TempDir(), imageRoot: imageRoot,
				detect: func() (*platform.Platform, error) {
					p := fakeHost()
					p.OS, p.ImageArch = tc.os, tc.arch

					return p, nil
				},
			}

			var obj map[string]interface{}
			if err := yaml.Unmarshal([]byte(machineDoc), &obj); err != nil {
				t.Fatal(err)
			}
			m := &unstructured.Unstructured{Object: obj}
			m.SetUID("bootstrap-default-cp0")

			opts, err := upOptions(d, m, driverkit.Absent, nil)
			if err != nil {
				t.Fatalf("upOptions: %v", err)
			}

			if opts.DisableKexec != tc.want {
				t.Errorf("DisableKexec = %v on %s/%s, want %v\n  reason: %s",
					opts.DisableKexec, tc.os, tc.arch, tc.want, tc.reason)
			}
		})
	}
}

// A VM already running is ADOPTED, not duplicated — the same already-exists
// rule -apply applies, and what makes `-apply` then `-up` a working sequence.
// Starting a second qemu against one state dir corrupts the disk they share.
func TestUpOptionsAdoptsAnAlreadyRunningVM(t *testing.T) {
	imageRoot := t.TempDir()
	writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
	// The host IS probed, even for a VM already running: step 1 of the
	// transcript is this host's facts, and cluster.Up cannot resolve them any
	// more. What adoption forbids is STARTING a second qemu, and Boot below is
	// what proves that — detect returning a platform is not a create().
	d := &hvf{
		stateRoot: t.TempDir(),
		imageRoot: imageRoot,
		detect:    func() (*platform.Platform, error) { return fakeHost(), nil },
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(machineDoc), &obj); err != nil {
		t.Fatal(err)
	}
	m := &unstructured.Unstructured{Object: obj}
	m.SetUID("bootstrap-default-cp0")

	opts, err := upOptions(d, m, driverkit.Running, map[string]interface{}{"pid": int64(4242)})
	if err != nil {
		t.Fatalf("upOptions: %v", err)
	}

	// Observe hands back an int64; a bare .(int) assertion would give 0 and
	// the transcript would report a VM with no process.
	pid, err := opts.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if pid != 4242 {
		t.Errorf("Boot returned pid %d, want the running VM's 4242", pid)
	}
}

// A STOPPED machine must NOT be adopted, and this is the sharp edge of the
// tri-state change.
//
// The adopt test is `state == Running`, and the tempting widening —
// `state != Absent` — is a hang, not a misprint. A stopped machine has disks
// and no process, so Observe's status is {stateDir} with no pid at all:
// toInt(nil) is 0, Boot would hand cluster.Up a VM whose process does not
// exist, qemu would never be started, and the bring-up would sit out its whole
// maintenance budget against an address nothing is listening on before failing
// with a timeout that blames the node.
//
// create() fails here on purpose, and its failure is the cheapest observable
// proof that Boot took the create() branch rather than the adopt one: an error
// means it tried to start a VM, nil would mean it adopted a pid that is not
// there. Detect can no longer be the thing that fails — upOptions needs the
// host facts for step 1 before Boot is ever called — so the firmware template
// is what is missing instead.
func TestUpOptionsDoesNotAdoptAStoppedVM(t *testing.T) {
	imageRoot := t.TempDir()
	writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
	d := &hvf{
		stateRoot: t.TempDir(),
		imageRoot: imageRoot,
		detect: func() (*platform.Platform, error) {
			p := fakeHost()
			p.FirmwareVars = filepath.Join(t.TempDir(), "absent-nvram-template.fd")

			return p, nil
		},
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(machineDoc), &obj); err != nil {
		t.Fatal(err)
	}
	m := &unstructured.Unstructured{Object: obj}
	m.SetUID("bootstrap-default-cp0")

	// Exactly what Observe returns for Stopped: a state dir and NO pid.
	opts, err := upOptions(d, m, driverkit.Stopped, map[string]interface{}{"stateDir": d.dir(m)})
	if err != nil {
		t.Fatalf("upOptions: %v", err)
	}

	pid, err := opts.Boot()
	if err == nil {
		t.Fatalf("Boot on a STOPPED machine returned pid %d and no error: it adopted a "+
			"process that does not exist instead of starting qemu, and the bring-up "+
			"below it would wait out its whole maintenance budget", pid)
	}
}

// spec.image is required, and an empty one must not resolve to the image ROOT:
// Stat succeeds on a directory, so without this guard -apply hands qemu a
// directory as its boot medium and -up reads a version out of one.
func TestResolveImageRequiresAProfile(t *testing.T) {
	d := &hvf{imageRoot: t.TempDir()}
	if _, err := d.resolveImage(map[string]interface{}{}); err == nil {
		t.Fatal("an absent spec.image must be an error")
	}
	if _, err := d.resolveImage(map[string]interface{}{"image": ""}); err == nil {
		t.Fatal("an empty spec.image must be an error")
	}
}

// upFixture writes a CR to disk and returns a driver whose Detect FAILS.
//
// That is the assertion, not the setup: teardown and an unresolvable image
// profile must both be settled before any host probing, because a machine that
// was never going to be created should not need a working hypervisor to say so.
//
// The endpoint refusals are the one exception and they override this — see
// TestUpRefusesAMachineWithNoForwardedEndpoint for why.
func upFixture(t *testing.T, doc string) (*hvf, string) {
	t.Helper()
	imageRoot := t.TempDir()
	writeSized(t, filepath.Join(imageRoot, "talos.iso"), 4096, 'I')
	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return &hvf{
		stateRoot: t.TempDir(),
		imageRoot: imageRoot,
		detect: func() (*platform.Platform, error) {
			t.Error("-up must refuse a machine it cannot reach before probing the host")
			return nil, fmt.Errorf("no accelerator on this host")
		},
	}, path
}

// A missing forward is refused UP FRONT, with the guest port named. Discovering
// it later costs a five- or ten-minute wait against an address that was never
// going to answer, and the transcript would blame the node.
func TestUpRefusesAMachineWithNoForwardedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		// machineDoc forwards 50000 and nothing else: a cluster whose
		// kubeconfig cannot be used from this host.
		{"no-kubernetes-forward", machineDoc, "6443"},
		{"no-forwards-at-all", strings.Split(machineDoc, "  hostForwards:")[0], "50000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, path := upFixture(t, tc.doc)
			// The endpoint refusal is cluster.Up's, and cluster.Up is reached
			// only once UpOptions is built — which now needs this host's facts
			// for step 1's line. So this one refusal lands AFTER the probe,
			// and upFixture's failing detect would report the wrong problem.
			d.detect = func() (*platform.Platform, error) { return fakeHost(), nil }

			err := standalone(context.Background(), d, path, "up")
			if err == nil {
				t.Fatal("-up ran against a machine with no forwarded endpoint")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name guest port %s: %v", tc.want, err)
			}
		})
	}
}

// -up needs the SAME image create() boots: its volume id is what pins the
// installer. An unresolvable profile has to fail here, not after a VM exists.
func TestUpRefusesAnUnresolvableImage(t *testing.T) {
	doc := strings.Replace(machineDoc, "image: talos.iso", "image: absent.iso", 1)
	d, path := upFixture(t, doc)
	err := standalone(context.Background(), d, path, "up")
	if err == nil {
		t.Fatal("-up ran with an image profile that resolves to nothing")
	}
	if !strings.Contains(err.Error(), "absent.iso") {
		t.Errorf("the refusal does not name the profile: %v", err)
	}
}

// -destroy is teardown, and teardown must NEVER require a healthy cluster, a
// reachable node or a working hypervisor. Adding -up beside it is exactly the
// change that could quietly make it need one.
func TestDestroyNeedsNoAcceleratorAndNoNode(t *testing.T) {
	d, path := upFixture(t, machineDoc)

	dir := filepath.Join(d.stateRoot, "testsite", "bootstrap-default-cp0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A LIVE process standing in for qemu, so this is the real teardown path
	// and not the trivially-absent one. It has to be a DECOY carrying the
	// state dir in its argv, not any old `sleep`: destroy signals nothing it
	// cannot prove is this machine's qemu, so an unrelated process would be
	// left alone and the ladder would never be entered.
	pid := startDecoy(t, dir)

	// The bring-up artifacts. They live in the state dir precisely so teardown
	// sweeps them and the cluster's secrets do not outlive the cluster.
	// system.qcow2 is among them because Observe keys Absent on it: without a
	// disk this machine reads as already gone and `destroy` returns before
	// touching anything.
	for _, name := range []string{"qemu.pid", "system.qcow2", "talosconfig", "kubeconfig", "secrets.yaml", "controlplane.yaml"} {
		body := "secret"
		if name == "qemu.pid" {
			body = fmt.Sprint(pid)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := standalone(context.Background(), d, path, "destroy"); err != nil {
		t.Fatalf("destroy must work with no accelerator and no reachable node: %v", err)
	}

	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d survived destroy", pid)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the state dir survived -destroy (%v)\n"+
			"  reason: the generated talosconfig, kubeconfig and secrets bundle live in it, and "+
			"secrets that outlive their cluster are residue with a private key in it", err)
	}
}

// Detect resolves FirmwareVars by statting it, so this is unreachable in
// practice — but it is the difference between a named error and a silent
// nil-deref if that ever stops holding.
func TestEnsureEFIVarsMissingTemplate(t *testing.T) {
	dir := t.TempDir()
	err := ensureEFIVars(filepath.Join(dir, "efivars.fd"), filepath.Join(dir, "absent.fd"))
	if err == nil {
		t.Fatal("a missing nvram template must be an error")
	}
	if !strings.Contains(err.Error(), "absent.fd") {
		t.Errorf("error must name the template, got: %v", err)
	}
}

// ── power state: Absent, Stopped, Running ───────────────────────────────────

// testMachine builds the minimum CR that dir() keys on: site and UID are the
// two path components, so a machine missing either would collide with another.
func testMachine(t *testing.T, site, uid string) *unstructured.Unstructured {
	t.Helper()
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "machine.hvf.fleet.io/v1alpha1",
		"kind":       "TalosMachine",
		"metadata":   map[string]interface{}{"name": "t", "namespace": "default"},
		"spec":       map[string]interface{}{"site": site},
	}}
	m.SetUID(types.UID(uid))
	return m
}

func TestObserveReportsAbsentWithoutSystemDisk(t *testing.T) {
	dir := t.TempDir()
	h := &hvf{stateRoot: dir}
	m := testMachine(t, "site-a", "uid-1")

	state, _, err := h.Observe(context.Background(), m)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if state != driverkit.Absent {
		t.Fatalf("Observe = %v, want Absent when system.qcow2 is missing", state)
	}
}

func TestObserveReportsAbsentWhenDirExistsButDiskDoesNot(t *testing.T) {
	// A create that died before qemu-img leaves the dir and no disk. Keying
	// Absent on the dir would read Stopped here and Create would never retry.
	root := t.TempDir()
	h := &hvf{stateRoot: root}
	m := testMachine(t, "site-a", "uid-1")
	if err := os.MkdirAll(h.dir(m), 0o755); err != nil {
		t.Fatal(err)
	}
	state, _, err := h.Observe(context.Background(), m)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if state != driverkit.Absent {
		t.Fatalf("Observe = %v, want Absent: dir exists but system.qcow2 does not", state)
	}
}

func TestObserveReportsStoppedWhenDisksExistButNoProcess(t *testing.T) {
	root := t.TempDir()
	h := &hvf{stateRoot: root}
	m := testMachine(t, "site-a", "uid-1")

	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "system.qcow2"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pidfile naming a pid that is alive but is NOT our qemu: this test binary.
	// Before ProcessMatches this reported Running, which is the bug.
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}

	state, _, err := h.Observe(context.Background(), m)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if state != driverkit.Stopped {
		t.Fatalf("Observe = %v, want Stopped: the live pid is not this machine's qemu", state)
	}
}

// destroy must not signal a pid it has not proven is this machine's qemu. The
// pidfile below names THIS TEST BINARY — alive and signalable, like the
// low-numbered stranger a reallocated pid hands you after a host reboot. An
// ungated SIGTERM therefore kills the test run outright rather than reporting a
// failure, which is the honest blast radius: on a real host it is another
// machine's qemu that dies.
func TestDestroyDoesNotSignalAPidItCannotProveIsOurs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "site-a", "uid-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := destroy(context.Background(), dir); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	// Still idempotent: an unkillable pid must not stop the sweep.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state dir must be gone, stat = %v", err)
	}
}

func TestStopIsIdempotentOnAnAbsentMachine(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	if err := h.Stop(context.Background(), m); err != nil {
		t.Fatalf("Stop on an absent machine = %v, want nil (idempotent)", err)
	}
}

func TestStopIsIdempotentOnAStoppedMachine(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "system.qcow2"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(context.Background(), m); err != nil {
		t.Fatalf("Stop on a stopped machine = %v, want nil (idempotent)", err)
	}
}

// startDecoy launches a live process whose argv carries dir, so
// platform.ProcessMatches accepts it as this machine's qemu.
//
// That is the only way to reach Stop's signal ladder without a hypervisor:
// Observe reports Running solely on a VERIFIED process, so a fabricated pidfile
// naming some unrelated pid reads Stopped and the ladder is never entered.
//
// The `while` loop is not decoration. `sh -c 'sleep 30' X` is a single simple
// command, which every real sh optimises into an exec: the shell replaces itself
// with sleep and the dir token disappears from argv. ProcessMatches would then
// report false and the caller would silently test nothing.
//
// The argv carries a path UNDER dir rather than the bare dir, because that is
// what qemu carries (-pidfile <dir>/qemu.pid) and ProcessMatches matches at the
// path boundary. A bare dir would no longer match, and every test resting on
// this decoy would pass vacuously by never entering the ladder at all.
func startDecoy(t *testing.T, dir string) int {
	t.Helper()
	return startDecoyRunning(t, dir, "while :; do sleep 1; done")
}

// startDecoyRunning is startDecoy with the shell script under the caller's
// control, so a test can make the decoy IGNORE SIGTERM. Args after the script
// are the shell's $0, $1, ...; the state-dir path goes last, where it is inert.
func startDecoyRunning(t *testing.T, dir, script string, extra ...string) int {
	t.Helper()
	args := append([]string{"-c", script, "qemu-decoy"}, extra...)
	args = append(args, "-pidfile", filepath.Join(dir, "qemu.pid"))
	cmd := exec.Command("sh", args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Reap it however the test ends. A decoy that outlives a failing test is a
	// stray process on someone's laptop, spinning until they notice.
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Wait for the argv to become VISIBLE, which is not the same as the process
	// existing. cmd.Start returns once exec has succeeded, but the kernel
	// publishes the new mm's arg_start/arg_end a moment later, so
	// /proc/<pid>/cmdline reads EMPTY for a short window and ProcessMatches
	// reports false for a live process that is genuinely ours. Observed here as
	// a ~1-in-4 flake before this loop existed.
	//
	// This is synchronisation, not a workaround: the decoy stands in for a qemu
	// that has been up for a while, and a half-exec'd process is not that.
	//
	// The window is real, and closing it in ProcessMatches is DEFERRED, not
	// impossible — the difference matters, because "impossible" would stop
	// anyone from trying. A fresh exec and a ZOMBIE are indistinguishable on
	// the command line (measured: both give a zero-length cmdline with a nil
	// error), but not on process state: /proc/<pid>/stat field 3 reads R for
	// the one and Z for the other, and darwin's `ps -o state=` draws the same
	// line. What blocks the fix is semantics, not capability. Reading an empty
	// cmdline as "gone" is exactly what stops destroy's wait from burning its
	// full deadline and then SIGKILLing a corpse, so teaching ProcessMatches
	// about process state changes the answer that wait loop depends on. That
	// is a design decision, not a patch, and it is left to whoever needs it.
	pid := cmd.Process.Pid
	deadline := time.Now().Add(2 * time.Second)
	for !platform.ProcessMatches(pid, dir) {
		if time.Now().After(deadline) {
			t.Fatalf("decoy %d never carried %q in its argv, so nothing below is exercised", pid, dir)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return pid
}

// startStubbornDecoy is startDecoy that REFUSES to die on SIGTERM, and records
// having received it by touching marker.
//
// An ordinary decoy dies on either signal, which makes the rungs of the ladder
// mutually redundant: delete the SIGKILL and SIGTERM still ends it, delete the
// SIGTERM and SIGKILL still ends it, shrink the budget to a nanosecond and it
// still ends. Four independent mutations all left the suite green. Only a
// process that SIGTERM cannot kill separates the rungs, and only the marker
// proves the first rung was ever climbed rather than skipped.
//
// The trap fires after the running `sleep` returns, so the marker appears
// within about a second — an order of magnitude inside the 5s budget, which is
// what keeps this an assertion rather than a race.
//
// Waiting for argv to become visible is NOT enough here, and the difference is
// a real race that was observed, not anticipated: the kernel publishes argv at
// exec, which is before the shell has parsed and run `trap`. A SIGTERM landing
// in that window takes the default action and the decoy dies on the first rung
// — the test then reports "halt skipped SIGTERM" for a halt that did send it.
// So the script announces the installed trap by touching a ready file, and the
// helper blocks on that. Observable readiness, not a sleep.
func startStubbornDecoy(t *testing.T, dir, marker string) int {
	t.Helper()
	ready := marker + ".ready"
	pid := startDecoyRunning(t, dir,
		`trap 'touch "$2"' TERM; touch "$1"; while :; do sleep 1; done`, ready, marker)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("decoy %d never installed its SIGTERM trap; it would die on the first rung "+
				"and the escalation below would never be exercised", pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The escalation ladder itself: SIGTERM first, the full budget, then SIGKILL.
//
// Every assertion below pins a rung a mutation was observed to survive:
//   - the marker pins that SIGTERM is SENT (delete it and SIGKILL still works)
//   - the elapsed floor pins the BUDGET (set sigtermTimeout to 1ns and the
//     process still dies, just instantly)
//   - the nil error and the identity check pin SIGKILL (delete it and a
//     SIGTERM-proof process is never stopped at all)
//
// Parallel with the destroy case below so the two 5s waits overlap: the ladder
// costs the suite one budget, not two.
func TestHaltEscalatesToSIGKILLWhenSIGTERMIsIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	marker := filepath.Join(dir, "sigterm-received")
	pid := startStubbornDecoy(t, dir, marker)

	start := time.Now()
	err := halt(context.Background(), pid, dir)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("halt = %v, want nil: SIGKILL must end a process SIGTERM cannot", err)
	}

	if _, statErr := os.Stat(marker); statErr != nil {
		t.Errorf("the decoy never received SIGTERM (%v): halt skipped the graceful rung "+
			"and went straight to SIGKILL, which is the silent-hard-kill this ladder exists to avoid", statErr)
	}
	if elapsed < sigtermTimeout {
		t.Errorf("halt returned after %v, inside the %v SIGTERM budget: it escalated without "+
			"giving the process its time to exit cleanly", elapsed, sigtermTimeout)
	}
	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d is still this machine's qemu after %v: the ladder never reached SIGKILL",
			pid, elapsed)
	}
}

// A cancelled context must cut the wait short, PROMPTLY, and must not report
// success.
//
// The bug: waitGone took no context and polled with a bare time.Sleep, and
// driverkit.Run only looks at ctx BETWEEN reconcile ticks. A Ctrl-C during a
// stop was therefore ignored for up to ~85s (15s shutdown RPC + 60s graceful +
// 5s SIGTERM + 5s SIGKILL). Elapsed time IS the assertion here: cancel at 200ms
// against a 5s rung, and anything near the budget means the wait was deaf again.
//
// The stubborn decoy is load-bearing twice over: it survives SIGTERM, so the
// wait is genuinely entered rather than satisfied instantly, and its SURVIVAL
// proves cancellation did not escalate. Measured against the sleeping version:
// this returned nil after 5.0s having SIGKILLed the decoy — late, escalated, and
// reporting success for a machine it had only just killed by force.
//
// Non-vacuity is the elapsed FLOOR, not the decoy's SIGTERM marker. The marker
// cannot be used here: the shell runs a trap only after the foreground `sleep`
// returns, so it lags by up to a second — longer than the window this test
// exists to measure, and asserting on it fails every time. The floor proves the
// same thing for this test's purpose: a halt that took its early return, or
// never entered a wait, cannot spend 200ms doing it.
func TestHaltAbandonsTheWaitWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pid := startStubbornDecoy(t, dir, filepath.Join(dir, "sigterm-received"))

	// Long enough that halt is demonstrably inside the wait when it lands, two
	// orders of magnitude short of the 5s rung it is interrupting.
	const cancelAfter = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), cancelAfter)
	defer cancel()

	start := time.Now()
	err := halt(ctx, pid, dir)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("halt = nil after %v on a cancelled context: the process is still running "+
			"and the caller has just been told it stopped", elapsed)
	}
	if elapsed < cancelAfter {
		t.Fatalf("halt returned in %v, before the context was even cancelled: it never "+
			"entered the wait, so the deadline below proves nothing", elapsed)
	}
	if elapsed > time.Second {
		t.Errorf("halt took %v to notice cancellation; the whole point is that Ctrl-C is "+
			"observed within a poll interval, not at the end of the %v budget", elapsed, sigtermTimeout)
	}
	if !platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d is gone: a cancelled halt escalated to SIGKILL. Ctrl-C means "+
			"stop what you are doing, not kill it harder", pid)
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("error %q does not name cancellation; an operator has to be able to tell "+
			"an abandoned stop from a failed one", err)
	}
}

// A cancelled teardown must NOT sweep the state dir.
//
// The ladder stopped early, so the qemu is probably still live with
// system.qcow2 open — removing the dir under it is corruption with a running
// writer, not a teardown. Blocking is safe because destroy is idempotent and the
// finalizer holds until a later tick succeeds.
//
// This pins the decision separately from halt's because it is a different one:
// destroy deliberately SWALLOWS an ordinary halt failure and sweeps anyway
// (TestDestroyDoesNotSignalAPidItCannotProveIsOurs pins that), and cancellation
// is the one case that must not take that path.
func TestDestroyDoesNotSweepStateWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	marker := filepath.Join(root, "sigterm-received")
	dir := filepath.Join(root, "site-a", "uid-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pid := startStubbornDecoy(t, dir, marker)
	disk := filepath.Join(dir, "system.qcow2")
	if err := os.WriteFile(disk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}

	const cancelAfter = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), cancelAfter)
	defer cancel()

	start := time.Now()
	err := destroy(ctx, dir)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("destroy = nil after %v on a cancelled context: deletion would proceed "+
			"with the VM still up", elapsed)
	}
	if elapsed < cancelAfter {
		t.Fatalf("destroy returned in %v, before the context was cancelled: it never "+
			"entered the wait", elapsed)
	}
	if elapsed > time.Second {
		t.Errorf("destroy took %v to notice cancellation, against a %v rung", elapsed, sigtermTimeout)
	}
	if _, statErr := os.Stat(disk); statErr != nil {
		t.Errorf("the disk was deleted (%v) while its qemu is still live: an abandoned "+
			"teardown must leave the state dir for the next tick", statErr)
	}
}

// A machine whose process is already gone must destroy CLEANLY even on a dead
// context. Teardown may not require a live hypervisor or a reachable node, and
// the cancellation handling above is one `ctx.Err() != nil` away from breaking
// that for every already-stopped machine.
func TestDestroyOfAnAlreadyGoneMachineSucceedsOnACancelledContext(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "site-a", "uid-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A pid that is nobody's: halt's gate returns before any wait, so there is
	// nothing for cancellation to interrupt.
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := destroy(ctx, dir); err != nil {
		t.Fatalf("destroy on an already-gone machine = %v, want nil: a cancelled context "+
			"must not wedge a finalizer that has nothing left to wait for", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state dir must be gone, stat = %v", err)
	}
}

// destroy climbs the SAME ladder. Pinned separately because the two used to be
// two copies of it — one gated on ProcessMatches, one not — and that
// divergence is exactly how an ungated first signal survives review. If a
// future edit re-inlines a private loop here, this fails.
//
// The marker lives OUTSIDE the state dir on purpose: destroy deletes the dir,
// so a marker inside it would be swept before it could be read.
func TestDestroyEscalatesToSIGKILLAndStillSweepsTheState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	marker := filepath.Join(root, "sigterm-received")
	dir := filepath.Join(root, "site-a", "uid-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pid := startStubbornDecoy(t, dir, marker)
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := destroy(context.Background(), dir); err != nil {
		t.Fatalf("destroy = %v, want nil", err)
	}
	elapsed := time.Since(start)

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the decoy never received SIGTERM (%v): destroy skipped the first rung", err)
	}
	if elapsed < sigtermTimeout {
		t.Errorf("destroy returned after %v, inside the %v SIGTERM budget", elapsed, sigtermTimeout)
	}
	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d survived destroy: the ladder never reached SIGKILL", pid)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("state dir must be gone, stat = %v", err)
	}
}

// The ladder with a real process on the end of it, and the property that is the
// entire reason Stop is not Destroy: the disks survive.
//
// The two idempotence tests above return before signalling anything, so without
// this one every line of the escalation is unexecuted code.
func TestStopHaltsAVerifiedProcessAndKeepsTheDisks(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "system.qcow2")
	if err := os.WriteFile(disk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := startDecoy(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	// A precondition, not a restatement: if this is not Running then Stop takes
	// its early return and every assertion below passes for the wrong reason.
	if state, _, err := h.Observe(context.Background(), m); err != nil || state != driverkit.Running {
		t.Fatalf("Observe = %v, %v before Stop; want Running or the ladder is never entered", state, err)
	}

	if err := h.Stop(context.Background(), m); err != nil {
		t.Fatalf("Stop = %v, want nil", err)
	}
	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d is still this machine's qemu; Stop did not halt it", pid)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("Stop must KEEP the disks — that is what separates it from Destroy: %v", err)
	}
	// Stopped, not Absent: the machine is still there, it is just not running.
	// This is the state the controller holds a powerState: Stopped machine in.
	state, _, err := h.Observe(context.Background(), m)
	if err != nil {
		t.Fatalf("Observe after Stop: %v", err)
	}
	if state != driverkit.Stopped {
		t.Fatalf("Observe after Stop = %v, want Stopped", state)
	}
}

// The `stop` CLI verb, end to end through standalone.
//
// The failure this pins is not "Stop does not work" — that is covered above.
// It is the DISPATCH: standalone's switch falls through to its apply branch for
// any verb it does not recognise, so a `stop` that never reaches the "stop"
// case leaves the VM alive. Verified by mutation: rename the case and this
// reports "already running", returns nil, and the process below is still ours —
// a silent no-op that an exit code would never expose.
//
// detect is left nil ON PURPOSE. Nothing on this path may probe the host, and a
// fall-through that got as far as Create would nil-deref here rather than
// quietly booting a machine someone asked to halt.
func TestStandaloneStopHaltsAndDoesNotFallThroughToCreate(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	// The UID standalone derives for a file with no metadata.uid, so the state
	// dir below is the one it will look in.
	m := testMachine(t, "site-a", "bootstrap-default-t")
	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "system.qcow2")
	if err := os.WriteFile(disk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := startDecoy(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "machine.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata: {name: t, namespace: default}
spec:
  site: site-a
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := standalone(context.Background(), h, path, "stop"); err != nil {
		t.Fatalf("standalone stop = %v, want nil", err)
	}
	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d is still this machine's qemu; stop did not halt it", pid)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("stop must KEEP the disks — that is what separates it from destroy: %v", err)
	}
}

// withTalosForward gives m a host forward to the Talos API, so talosEndpoint(m)
// is non-empty. Port 1 rather than 50000: nothing may actually connect here,
// and a real forward port could collide with a developer's running VM.
func withTalosForward(t *testing.T, m *unstructured.Unstructured) {
	t.Helper()
	if err := unstructured.SetNestedSlice(m.Object, []interface{}{
		map[string]interface{}{"guestPort": int64(talosAPIGuestPort), "hostPort": int64(1)},
	}, "spec", "hostForwards"); err != nil {
		t.Fatal(err)
	}
	if talosEndpoint(m) == "" {
		t.Fatal("fixture is wrong: talosEndpoint is still empty, so the client is refused " +
			"before the talosconfig is read and the test below proves nothing")
	}
}

// A machine still in MAINTENANCE MODE has no talosconfig, and must be refused
// immediately rather than dialled.
//
// The deadline is the assertion. `apply` creates machines that never get one,
// and the graceful rung is entered on every `stop` of a Running machine — so a
// shutdownGuest that reached for the network here would make the ordinary
// maintenance-mode stop wait out a dial timeout before it could signal
// anything. Fast is the behaviour, not merely the outcome.
func TestShutdownGuestFailsFastOnAMachineWithNoTalosconfig(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	if err := os.MkdirAll(h.dir(m), 0o755); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err := h.shutdownGuest(context.Background(), m)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("shutdownGuest with no talosconfig = nil: Stop would then wait out its "+
			"whole %v graceful budget for a power-off nobody was ever asked for", gracefulStopTimeout)
	}
	// Two orders of magnitude under shutdownRequestTimeout: this must be a
	// file-not-found, not a dial that happened to fail quickly.
	if elapsed > time.Second {
		t.Errorf("shutdownGuest took %v to refuse a machine with no talosconfig; it must not "+
			"reach the network to discover it has no credentials", elapsed)
	}
	if !strings.Contains(err.Error(), "talosconfig") {
		t.Errorf("error %q does not name talosconfig; Stop logs this verbatim and the "+
			"operator has to be able to tell maintenance mode from a broken node", err)
	}
}

// The talosconfig is a PRIVATE KEY and must never appear in an error.
//
// cluster.errSecretParse withholds even the parser's own message for this
// reason; the failure guarded here is a wrapper on THIS side quoting the bytes
// that the cluster package took care not to. Stop prints whatever comes back,
// so a leak lands in the operator's terminal and their CI log.
func TestShutdownGuestNeverQuotesTheTalosconfig(t *testing.T) {
	const secret = "TOTALLY-NOT-A-REAL-PRIVATE-KEY-8f3a1c"

	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	// A Talos forward is a PRECONDITION, not decoration: AuthenticatedClient
	// refuses an empty endpoint before it ever looks at the bytes, so without
	// this the parse is never reached and the assertion below passes
	// vacuously.
	withTalosForward(t, m)
	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Unterminated flow sequence: this must fail in the YAML PARSER, which is
	// the one failure with the whole document in scope to quote. Well-formed
	// YAML that merely lacks a context fails later, in client.New, with
	// nothing but its own words — a weaker case, and not the one
	// cluster.errSecretParse exists for.
	if err := os.WriteFile(filepath.Join(dir, "talosconfig"),
		[]byte("context: ["+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := h.shutdownGuest(context.Background(), m)
	if err == nil {
		t.Fatal("shutdownGuest on an unparseable talosconfig = nil, want an error")
	}
	// Pins the fixture to the parser: if a future machinery accepts this
	// document, the assertion below would be guarding the wrong failure.
	if !strings.Contains(err.Error(), "could not be parsed") {
		t.Fatalf("fixture no longer fails in the parser (%v); the leak this guards "+
			"against is the parser's message quoting the document", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error quotes the talosconfig: %q\n"+
			"  that document is a private key, and Stop logs this", err)
	}
}

// A failed graceful shutdown must FALL THROUGH to the signal ladder, and say so.
//
// This is the property that keeps a wedged guest stoppable: the graceful rung
// is best-effort, never a precondition. Distinct from
// TestStopHaltsAVerifiedProcessAndKeepsTheDisks above, which reaches the ladder
// with NO talosconfig at all — here one exists and the client build is what
// fails, so the fall-through is proven for the dial/credential path too, which
// is the one a real broken node takes.
//
// The log line is asserted because silence is the specific failure: a stop that
// hard-kills without announcing it is how you find out months later that none
// of your stops were ever clean.
func TestStopFallsBackToSignalsWhenTheGuestCannotBeAsked(t *testing.T) {
	h := &hvf{stateRoot: t.TempDir()}
	m := testMachine(t, "site-a", "uid-1")
	// So the failure below is a CREDENTIAL failure and not "no endpoint" —
	// the machine looks reachable and the talosconfig is what is wrong, which
	// is the shape a real broken node has.
	withTalosForward(t, m)
	dir := h.dir(m)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "system.qcow2")
	if err := os.WriteFile(disk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "talosconfig"),
		[]byte("not a talosconfig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid := startDecoy(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "qemu.pid"),
		[]byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Without Running, Stop takes its early return and everything below passes
	// for the wrong reason.
	if state, _, err := h.Observe(context.Background(), m); err != nil || state != driverkit.Running {
		t.Fatalf("Observe = %v, %v before Stop; want Running or the ladder is never entered", state, err)
	}

	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := h.Stop(context.Background(), m); err != nil {
		t.Fatalf("Stop = %v, want nil: a guest that cannot be asked must still be stoppable", err)
	}
	if platform.ProcessMatches(pid, dir) {
		t.Errorf("process %d is still this machine's qemu: a failed graceful shutdown "+
			"became a failed stop", pid)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("Stop must KEEP the disks: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "falling back to signals") {
		t.Errorf("Stop hard-killed the VM without announcing it; log was %q", out)
	}
}

// kill(0, sig) is NOT a no-op: POSIX sends the signal to every process in the
// CALLER's process group. readPid returns 0 for a pidfile that has vanished —
// which a concurrent destroy causes, since it removes the whole state dir — so
// an ungated ladder would SIGTERM and then SIGKILL tinq and everything sharing
// its group.
//
// There is no assertion for that beyond survival, and the blast radius is
// wider than one process: drop the guard and kill(0, sig) takes the whole
// PROCESS GROUP — this test binary, the `go test` that spawned it, and
// anything else sharing that group — mid-run. That is strictly wider than
// TestDestroyDoesNotSignalAPidItCannotProveIsOurs above, which names a single
// pid and so kills exactly one process. Recorded here because the symptom is a
// CI job that dies without a failing test to explain it, and this file is
// where someone bisecting that will end up.
func TestHaltRefusesToSignalPidZero(t *testing.T) {
	if err := halt(context.Background(), 0, t.TempDir()); err != nil {
		t.Fatalf("halt(ctx, 0, dir) = %v, want nil", err)
	}
}

// halt's FIRST signal must be gated too, not just the escalation.
//
// The pid below is live, signalable, and not ours — the low-numbered stranger a
// recycled pid hands you after a host reboot, and on a real host plausibly
// another machine's qemu. Stop reaches here with a pid it re-read from the
// pidfile rather than the one Observe verified, and the likeliest graceful
// failure is an error CAUSED by the guest going away, so this is the ordinary
// path, not a corner.
//
// Measured against the ungated version: halt returned nil in ~10µs having
// SIGTERMed the stranger — and reported SUCCESS, because waitGone read the
// non-match as "gone". A caller could not have noticed.
//
// Liveness is read from Wait, not kill(pid,0): the stranger is our child, so a
// dead one lingers as a ZOMBIE that kill(pid,0) calls alive. Wait is the only
// reading that tells "still running" from "we just killed it".
func TestHaltRefusesToSignalAPidItCannotProveIsOurs(t *testing.T) {
	dir := t.TempDir() // nothing anywhere carries this token

	stranger := exec.Command("sh", "-c", "while :; do sleep 1; done")
	if err := stranger.Start(); err != nil {
		t.Fatal(err)
	}
	pid := stranger.Process.Pid
	defer func() { _ = stranger.Process.Kill() }()

	died := make(chan struct{})
	go func() { _ = stranger.Wait(); close(died) }()

	// Guard against a vacuous pass: if the stranger already matched, halt would
	// be right to signal it and the assertion below would prove nothing.
	if platform.ProcessMatches(pid, dir) {
		t.Fatalf("fixture is wrong: stranger %d matches %q", pid, dir)
	}

	if err := halt(context.Background(), pid, dir); err != nil {
		t.Fatalf("halt on an unprovable pid = %v, want nil", err)
	}
	select {
	case <-died:
		t.Fatalf("halt signalled pid %d, which it never proved was this machine's qemu", pid)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestEndpointsHonourHostAddr(t *testing.T) {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"hostForwards": []interface{}{
			map[string]interface{}{"hostPort": int64(50000), "guestPort": int64(50000),
				"hostAddr": "192.168.1.165"},
			map[string]interface{}{"hostPort": int64(6443), "guestPort": int64(6443),
				"hostAddr": "192.168.1.165"},
		}},
	}}

	if got := talosEndpoint(m); got != "192.168.1.165:50000" {
		t.Errorf("talosEndpoint = %q, want 192.168.1.165:50000\n"+
			"  reason: qemu binds the forward to hostAddr ONLY, so dialling loopback "+
			"reaches nothing and spends the whole maintenance budget proving it", got)
	}

	if got := kubeEndpoint(m); got != "https://192.168.1.165:6443" {
		t.Errorf("kubeEndpoint = %q, want https://192.168.1.165:6443\n"+
			"  reason: this address is written into the kubeconfig AND becomes the "+
			"cert SAN, so a wrong one fails every kubectl call", got)
	}
}

// The default is the regression that matters: an entry with no hostAddr must
// still produce loopback, because that is what every existing machine file has.
func TestEndpointsDefaultToLoopbackWithoutHostAddr(t *testing.T) {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"hostForwards": []interface{}{
			map[string]interface{}{"hostPort": int64(50000), "guestPort": int64(50000)},
		}},
	}}

	if got := talosEndpoint(m); got != "127.0.0.1:50000" {
		t.Errorf("talosEndpoint = %q, want 127.0.0.1:50000", got)
	}
}

// ── spec.registries ─────────────────────────────────────────────────────────
//
// The apiserver is NOT in this path. `up` and `adopt` read a machine file off
// disk, so the CRD's schema — which is where this field's shape is published —
// guarantees nothing at all here. registryMirrors is the only thing standing
// between a typo and a node configured to mirror nothing.

func TestRegistryMirrorsReadsTheList(t *testing.T) {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"registries": []interface{}{
			map[string]interface{}{
				"host":     "10.0.2.2:5000",
				"endpoint": "http://10.0.2.2:5000",
			},
			map[string]interface{}{
				"host":               "registry.lan",
				"endpoint":           "https://registry.lan/mirror",
				"insecureSkipVerify": true,
				"overridePath":       true,
			},
		}},
	}}

	got, err := registryMirrors(m)
	if err != nil {
		t.Fatalf("registryMirrors: %v", err)
	}

	want := []cluster.RegistryMirror{
		{Host: "10.0.2.2:5000", Endpoint: "http://10.0.2.2:5000"},
		{
			Host: "registry.lan", Endpoint: "https://registry.lan/mirror",
			InsecureSkipVerify: true, OverridePath: true,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("registryMirrors = %+v, want %+v", got, want)
	}
}

func TestRegistryMirrorsReadsInlineCA(t *testing.T) {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"registries": []interface{}{
			map[string]interface{}{
				"host": "registry.lab", "endpoint": "https://registry.lab",
				"ca": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
			},
		}},
	}}
	got, err := registryMirrors(m)
	if err != nil {
		t.Fatalf("registryMirrors: %v", err)
	}
	if len(got) != 1 || !strings.Contains(got[0].CA, "BEGIN CERTIFICATE") {
		t.Fatalf("inline ca not read: %+v", got)
	}
}

func TestRegistryMirrorsReadsCAFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/root.crt"
	if err := os.WriteFile(p, []byte("PEMBYTES"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"registries": []interface{}{
			map[string]interface{}{
				"host": "registry.lab", "endpoint": "https://registry.lab", "caFile": p,
			},
		}},
	}}
	got, err := registryMirrors(m)
	if err != nil {
		t.Fatalf("registryMirrors: %v", err)
	}
	if got[0].CA != "PEMBYTES" {
		t.Fatalf("caFile not read: %q", got[0].CA)
	}
}

// nil, not an empty slice, and it must not be an error: a machine with no
// mirrors is the normal case and cluster/config.go reads len() == 0 as "emit no
// registries section at all".
func TestRegistryMirrorsAbsentIsNotAnError(t *testing.T) {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"site": "testsite"},
	}}

	got, err := registryMirrors(m)
	if err != nil || got != nil {
		t.Errorf("registryMirrors = %+v, %v; want nil, nil — no mirrors is the default, "+
			"not a malformed file", got, err)
	}
}

// Each refusal is pinned to its own text. A single "invalid registries" error
// would pass this table while telling the operator nothing about WHICH of the
// three mistakes they made, and these three fail in three different ways: a
// scalar entry is a YAML indentation slip, a missing host is a key typo, and a
// scheme-less endpoint is the one that looks right and fails at image pull.
func TestRegistryMirrorsRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry interface{}
		says  string
	}{
		{"scalar-entry", "10.0.2.2:5000", "not a block of fields"},
		{"no-host", map[string]interface{}{"endpoint": "http://10.0.2.2:5000"}, "has no host"},
		{"empty-host", map[string]interface{}{"host": "", "endpoint": "http://x:5000"}, "has no host"},
		{
			"no-endpoint",
			map[string]interface{}{"host": "10.0.2.2:5000"},
			"has no http:// or https:// scheme",
		},
		{
			"scheme-less-endpoint",
			map[string]interface{}{"host": "10.0.2.2:5000", "endpoint": "10.0.2.2:5000"},
			"has no http:// or https:// scheme",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{"registries": []interface{}{tc.entry}},
			}}

			_, err := registryMirrors(m)
			if err == nil {
				t.Fatalf("registryMirrors accepted %v — a mirror the node cannot use is "+
					"worse than none, because it looks configured", tc.entry)
			}

			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error does not say %q:\n%v", tc.says, err)
			}
		})
	}
}
