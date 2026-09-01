package cluster

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v4"

	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/machinery/compatibility"
	"github.com/siderolabs/talos/pkg/machinery/config/configloader"
	"github.com/siderolabs/talos/pkg/machinery/config/generate/secrets"
)

// A generated machine config is five certificate authorities, the machine
// token and the cluster secrets — config.go says as much: "none of them is
// safe to log". A test that dumps one on a failed assertion puts all of it in
// a terminal, a CI log, and whatever the reporter pastes into an issue.
//
// So the rule in this file is: ANYTHING derived from generated material goes
// through redact() before it reaches t.Errorf, t.Fatalf or t.Logf — documents,
// and the errors machinery raises about them, which quote what they choked on.
//
// The shapes below are matched instead of the field names because field names
// drift with the schema: a secret machinery adds in some later version arrives
// already redacted, whereas a name list would silently let it through.
// TestRedactHidesEveryGeneratedSecret checks this holds against the real
// bundle rather than against this comment.
var secretShapes = []*regexp.Regexp{
	// Base64 blobs: every CA certificate and key, the service account key,
	// cluster.id, cluster.secret, secretboxEncryptionSecret. The shortest is
	// 44 characters. BOTH alphabets are covered — machinery emits standard
	// base64 (`+/`) for the certificates and URL-safe base64 (`-_`) for
	// cluster.id, which is how the first draft of this redactor leaked a
	// 44-character secret past a `[A-Za-z0-9+/]` class.
	//
	// `-` and `_` in the class make over-matching possible, and that is the
	// deliberate direction to err in: over-redaction costs a line of debug
	// output and is caught by TestRedactKeepsTheValuesTheAssertionsAreAbout,
	// under-redaction publishes a private key. The longest legitimate run in
	// these documents is 39 characters, and image references and CEL
	// expressions are broken up by `.`, `:` and `"` besides.
	regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`),
	// machine.token and cluster.token: bootstrap-token shaped, and only 23
	// characters, which is why no length threshold alone is safe here.
	regexp.MustCompile(`\b[a-z0-9]{6}\.[a-z0-9]{16}\b`),
	// Defence in depth. Machinery base64s its PEM today; if it ever stops,
	// the blob stops being base64-shaped and would otherwise sail through.
	regexp.MustCompile(`(?s)-----BEGIN[^-]*-----.*?-----END[^-]*-----`),
}

// redact replaces every secret-shaped run in s with its length, keeping the
// structure and the operational values the assertions are actually about.
func redact(s string) string {
	for _, re := range secretShapes {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			return fmt.Sprintf("<redacted %d chars>", len(m))
		})
	}

	return s
}

// redactErr renders an error with the same protection. Machinery's parse and
// validation errors quote the input they rejected.
func redactErr(err error) string {
	if err == nil {
		return "<nil>"
	}

	return redact(err.Error())
}

// testInput is the shape main.go passes: both serials come from the CALLER,
// because the constants live in package main and this package must not
// duplicate them — a duplicated literal drifts, and a drifted install selector
// matches no disk at all.
func testInput() ConfigInput {
	return ConfigInput{
		ClusterName:    "probe",
		Endpoint:       "https://127.0.0.1:6443",
		APIAddress:     "127.0.0.1",
		TalosVersion:   "v1.13.7",
		ConsoleArg:     "console=ttyS0",
		SystemDisk:     DiskRef{Serial: "talos-system"},
		DataDiskSerial: "talos-data",
	}
}

func mustGenerate(t *testing.T, in ConfigInput) *Generated {
	t.Helper()

	g, err := GenerateConfig(in)
	if err != nil {
		t.Fatalf("GenerateConfig(%+v): %s", in, redactErr(err))
	}

	return g
}

// Generating a config means generating five certificate authorities, which
// dominates the runtime of this package. The tests that use testInput()
// unchanged share one, read-only.
var defaultGenerated = sync.OnceValues(func() (*Generated, error) { return GenerateConfig(testInput()) })

func mustGenerateDefault(t *testing.T) *Generated {
	t.Helper()

	g, err := defaultGenerated()
	if err != nil {
		t.Fatalf("GenerateConfig(%+v): %s", testInput(), redactErr(err))
	}

	return g
}

// A Talos machine config is a MULTI-DOCUMENT YAML: v1alpha1 first, then any
// number of separate documents. Asserting on the whole blob cannot tell which
// document a string landed in, which is exactly how a swapped serial survives.
//
// The splitter itself lives in reconfigure.go, because the refusals there
// compare documents for real and a second copy of "what is a document" would
// let the tests and the production comparison disagree about it.

// The encoder documents every field it sets AND emits a commented-out example
// of most fields it did not. Asserting against that text is how a test for
// `allowSchedulingOnControlPlanes: true` passes on a config that sets it to
// false — the string really is in the file, in a comment. Four mutants survived
// this suite until every assertion was made to read the CODE, not the manual.
var comments = regexp.MustCompile(`(?m)^[ \t]*#.*$|[ \t]+#.*$`)

func code(doc string) string { return comments.ReplaceAllString(doc, "") }

// code() is load-bearing for four of this suite's mutants, and load-bearing
// with nothing under it: neuter it to `return doc` and every test above still
// passes, because every assertion it protects is then matched against the
// encoder's commented-out example instead of the config. Apply the
// allowSchedulingOnControlPlanes(false) mutant on top of that and the suite is
// STILL green. redact() has a keeps-what-matters test for the same reason;
// this is code()'s.
func TestCodeReadsTheConfigAndNotTheEncodersManual(t *testing.T) {
	// The encoder writes a commented-out example of most fields it did not
	// set, at the indentation the field would have had.
	for _, comment := range []string{
		"# allowSchedulingOnControlPlanes: true",
		"        # allowSchedulingOnControlPlanes: true",
		"\t# grubUseUKICmdline: true",
	} {
		if got := code(comment); strings.TrimSpace(got) != "" {
			t.Errorf("code(%q) = %q, want nothing\n"+
				"  reason: an assertion that can read a commented-out example passes on a config that "+
				"sets the opposite, and the mutant survives", comment, got)
		}
	}

	// A trailing comment goes without taking the setting with it.
	if got := code("    allowSchedulingOnControlPlanes: true # sets the thing"); !strings.Contains(got, "allowSchedulingOnControlPlanes: true") {
		t.Errorf("code() dropped the setting along with its trailing comment: %q", got)
	}

	// And a live line survives untouched — a code() that returns "" hides
	// every commented example AND every assertion, and the suite goes green by
	// vacuum instead of by evidence.
	if want := "    clusterName: probe"; code(want) != want {
		t.Errorf("code(%q) = %q, want it unchanged\n"+
			"  reason: a redactor of comments that eats the config makes every Contains() below "+
			"assert against an empty string", want, code(want))
	}
}

func v1alpha1Doc(t *testing.T, cp []byte) string {
	t.Helper()

	doc := code(splitDocs(cp)[0])
	if !strings.Contains(doc, "version: v1alpha1") {
		t.Fatalf("first document is not the v1alpha1 config:\n%s", redact(doc))
	}

	return doc
}

// docOfKindT is docOfKind with the encoder's commented-out examples stripped,
// which every assertion in this file needs and the production comparison must
// NOT have: a comment changing is still the document changing.
func docOfKindT(t *testing.T, cp []byte, kind string) (string, bool) {
	t.Helper()

	doc, ok := docOfKind(cp, kind)

	return code(doc), ok
}

// installSelector matches an install block that selects BY SERIAL. The
// indentation is the encoder's, and the pairing is the point: `serial:`
// anywhere in the file proves nothing about which disk Talos will install to.
var installSelector = regexp.MustCompile(`(?m)^ {8}diskSelector:\n {12}serial: (\S+)`)

func TestGenerateConfigInstallsToTheSystemDiskBySerial(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	m := installSelector.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("install has no diskSelector.serial\n"+
			"  reason: with two large disks a size matcher is a coin flip between the OS target and the data disk\n%s", redact(doc))
	}

	if m[1] != "talos-system" {
		t.Errorf("install selects serial %q, want %q\n"+
			"  reason: installing onto the DATA disk destroys the user volume and leaves the system disk empty", m[1], "talos-system")
	}

	if regexp.MustCompile(`(?m)^ {8}disk: `).MatchString(doc) {
		t.Error("install sets a device path\n" +
			"  reason: /dev/vdX ordering is not stable across boots; the serial is the identity")
	}
}

// A pinned installer is the whole point of testing an unreleased Talos: without
// it the node quietly installs whatever the ISO's version resolves to, and the
// only symptom is a version string nobody thinks to ask for.
func TestGenerateConfigPinsTheInstallerImageWhenAsked(t *testing.T) {
	in := testInput()
	in.InstallerImage = "ghcr.io/example/installer:patched"

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	if !regexp.MustCompile(`(?m)^ {8}image: ghcr\.io/example/installer:patched$`).MatchString(doc) {
		t.Errorf("install.image is not the pinned installer\n"+
			"  reason: machinery 1.14 accepts WithInstallImage and discards it when it "+
			"allocates no machine.install, so the node boots STOCK Talos\n%s", redact(doc))
	}
}

// The control for the case above: an unset field must not invent an image.
func TestGenerateConfigKeepsTheVersionPinnedInstallerByDefault(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	if !regexp.MustCompile(`(?m)^ {8}image: ghcr\.io/siderolabs/installer:`).MatchString(doc) {
		t.Errorf("install.image is not the version-pinned default\n"+
			"  reason: an unpinned installer silently becomes a cross-version install\n%s", redact(doc))
	}
}

// The serials belong to package main. If this package ever hardcodes them, the
// two halves drift the moment main.go renames one — and the failure is silent.
func TestGenerateConfigUsesTheCallersSerials(t *testing.T) {
	in := testInput()
	in.SystemDisk = DiskRef{Serial: "sys-9000"}
	in.DataDiskSerial = "data-9000"

	cp := mustGenerate(t, in).ControlPlane

	if m := installSelector.FindStringSubmatch(v1alpha1Doc(t, cp)); m == nil || m[1] != "sys-9000" {
		t.Errorf("install selector = %v, want serial sys-9000\n"+
			"  reason: the serials are main.go's constants; a literal copied into this package drifts silently", m)
	}

	vol, ok := docOfKindT(t, cp, "UserVolumeConfig")
	if !ok || !strings.Contains(vol, `disk.serial == "data-9000"`) {
		t.Errorf("user volume does not select data-9000\n"+
			"  reason: same drift, other half — the volume would match no disk and never appear\n%s", redact(vol))
	}
}

// installSelectorWWID is installSelector's other half. Two regexps rather than
// one with an alternation, because the pairing is the whole point: a test that
// accepted `serial:` OR `wwid:` would pass on a config that selects by the
// field the caller did NOT ask for.
var installSelectorWWID = regexp.MustCompile(`(?m)^ {8}diskSelector:\n {12}wwid: (.+)$`)

// THE DISK THIS WHOLE PATH EXISTS FOR: a USB bridge that reports no serial, so
// the only identity it has is a WWID — including the runs of spaces a real one
// contains.
func TestGenerateConfigInstallsByWWIDWhenThatIsTheIdentityGiven(t *testing.T) {
	const wwid = "t10.SSK     PCIe581         DD0000000000000C"

	in := testInput()
	in.SystemDisk = DiskRef{WWID: wwid}

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	m := installSelectorWWID.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("install has no diskSelector.wwid\n"+
			"  reason: a disk with no serial cannot be named any other way, and a selector "+
			"matching nothing installs nowhere while Talos reports a hang\n%s", redact(doc))
	}

	// The encoder may quote it — it contains spaces — but the VALUE has to
	// survive intact either way.
	if got := strings.Trim(m[1], `"'`); got != wwid {
		t.Errorf("install selects wwid %q, want %q\n"+
			"  reason: collapsed or truncated, it names no disk on the node", got, wwid)
	}

	// The two fields are ALTERNATIVES: machinery ANDs every non-empty field of
	// an InstallDiskSelector, so an emitted `serial:` beside the wwid would
	// demand one disk reporting both and match nothing.
	if installSelector.MatchString(doc) {
		t.Error("install emits a serial selector beside the wwid\n" +
			"  reason: machinery ANDs the fields, so both together match no disk at all")
	}
}

// SINGLE-DISK LAYOUT. EPHEMERAL is capped so there is free space at all, and
// the user volume takes the rest of the same disk. Both halves or neither: a
// cap with no user volume wastes the space, and a user volume with no cap has
// nowhere to go because EPHEMERAL grew to fill the disk.
func TestGenerateConfigCarvesTheSystemDiskWhenEphemeralIsCapped(t *testing.T) {
	in := testInput()
	in.DataDiskSerial = ""
	in.EphemeralMaxSize = "120GB"

	cp := mustGenerate(t, in).ControlPlane

	eph, ok := docOfKindT(t, cp, "VolumeConfig")
	if !ok {
		t.Fatalf("no VolumeConfig document\n"+
			"  reason: uncapped, EPHEMERAL grows to the size of the disk and the user "+
			"volume below has no free space to claim\n%s", redact(string(cp)))
	}

	for _, want := range []string{"name: EPHEMERAL", "maxSize: 120GB", "match: system_disk"} {
		if !strings.Contains(eph, want) {
			t.Errorf("the EPHEMERAL cap does not contain %q:\n%s", want, redact(eph))
		}
	}

	vol, ok := docOfKindT(t, cp, "UserVolumeConfig")
	if !ok {
		t.Fatalf("no UserVolumeConfig beside the EPHEMERAL cap\n" +
			"  reason: the cap alone frees space nothing then uses, and step 10 would " +
			"install a StorageClass provisioning into a mount point that does not exist")
	}

	if !strings.Contains(vol, "match: system_disk") {
		t.Errorf("the user volume does not select the system disk:\n%s\n"+
			"  reason: the install target may have been named by WWID, and re-deriving that "+
			"identity here is how the two drift apart", redact(vol))
	}

	if !strings.Contains(vol, "grow: true") {
		t.Errorf("the user volume does not grow:\n%s\n"+
			"  reason: without it the volume takes minSize and the space the cap freed is wasted", redact(vol))
	}
}

// The two routes to a user volume are alternatives, and the DEDICATED DISK one
// must not start capping EPHEMERAL as a side effect — that would repartition
// the system disk of every machine that already has a data disk.
func TestGenerateConfigLeavesEphemeralAloneWithADedicatedDataDisk(t *testing.T) {
	cp := mustGenerateDefault(t).ControlPlane

	if _, ok := docOfKindT(t, cp, "VolumeConfig"); ok {
		t.Error("a machine with a dedicated data disk still caps EPHEMERAL\n" +
			"  reason: nothing needs the space, and a cap is set at install time and " +
			"cannot be undone without a wipe")
	}
}

func TestGenerateConfigEmitsNoVolumeDocumentsWithNeither(t *testing.T) {
	in := testInput()
	in.DataDiskSerial = ""

	cp := mustGenerate(t, in).ControlPlane

	for _, kind := range []string{"VolumeConfig", "UserVolumeConfig"} {
		if _, ok := docOfKindT(t, cp, kind); ok {
			t.Errorf("a machine with no data disk and no cap still emits a %s\n"+
				"  reason: it must behave exactly as every machine did before either field existed", kind)
		}
	}
}

func TestEphemeralCapRefusesASizeTalosCannotParse(t *testing.T) {
	for _, tc := range []struct{ name, size string }{
		{"a bare number with no unit", "120"},
		{"words", "lots"},
		// "" reaches ephemeralCap only through a caller that has stopped
		// gating on non-empty — which would emit a cap that caps nothing.
		{"the empty string", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ephemeralCap(tc.size); err == nil {
				t.Errorf("ephemeralCap(%q) was accepted\n"+
					"  reason: a cap that does not bound EPHEMERAL leaves the user volume "+
					"nowhere to grow, and nothing fails to say so", tc.size)
			}
		})
	}
}

// THE PROPERTY RECONFIGURE IS BUILT ON, and the one whose failure cannot be
// undone on hardware: regenerating a config for a node that already exists must
// keep the PKI that node was installed with. A fresh bundle is five new
// certificate authorities and a new machine token — the node rejects the config
// as signed by a CA it does not trust, and the talosconfig generated beside it
// cannot authenticate to the node it is for. An installed node never serves the
// maintenance API again, so there is no way back.
func TestGenerateConfigReusesAnExistingSecretsBundle(t *testing.T) {
	first := mustGenerateDefault(t)

	in := testInput()
	in.SecretsBundle = first.Secrets
	// Something has to CHANGE, or this passes against a function that ignores
	// its input entirely.
	in.Registries = []RegistryMirror{{Host: "reg.lan:5000", Endpoint: "http://reg.lan:5000"}}

	second := mustGenerate(t, in)

	if !bytes.Equal(first.Secrets, second.Secrets) {
		t.Error("regenerating with an existing bundle minted a new one\n" +
			"  reason: new CAs mean the node rejects the config and the talosconfig cannot " +
			"reach it — unrecoverable on hardware")
	}

	// NOT byte equality: the client certificate is MINTED at generation time,
	// so a second run issues a different one with a different key and validity
	// window. That is fine — what has to hold is that it is signed by the CA
	// the node already trusts, which is the CA itself being unchanged.
	//
	// (Reconfigure never writes this file anyway; see writeArtifacts there. The
	// assertion is about the CA, not about the file's fate.)
	if a, b := talosconfigCA(t, first.Talosconfig), talosconfigCA(t, second.Talosconfig); a != b {
		t.Error("the regenerated talosconfig carries a DIFFERENT CA\n" +
			"  reason: the node authenticates against the CA it was installed with; a new one " +
			"locks us out of a machine that never serves the maintenance API again")
	}

	// And the change asked for actually landed, so the reuse is not simply
	// returning the first result.
	if !strings.Contains(v1alpha1Doc(t, second.ControlPlane), "reg.lan:5000") {
		t.Error("the regenerated config does not contain the new registry mirror")
	}
}

// talosconfigCA returns the CA a talosconfig verifies nodes against. It is a
// public certificate, so unlike the rest of the file it is safe to compare and
// to fail on.
func talosconfigCA(t *testing.T, talosconfig []byte) string {
	t.Helper()

	cfg, err := clientconfig.FromBytes(talosconfig)
	if err != nil {
		t.Fatalf("parsing a generated talosconfig: %v", err)
	}

	ctx, ok := cfg.Contexts[cfg.Context]
	if !ok {
		t.Fatalf("the talosconfig has no context named %q", cfg.Context)
	}

	return ctx.CA
}

// A secrets bundle that parses as YAML but is not a bundle would otherwise be
// noticed as a nil dereference inside machinery.
func TestGenerateConfigRefusesAnUnusableSecretsBundle(t *testing.T) {
	for _, tc := range []struct{ name, bundle string }{
		{"not yaml at all", "\tnot: [a bundle"},
		{"valid yaml, wrong document", "hello: world\n"},
		{"an empty document", "{}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput()
			in.SecretsBundle = []byte(tc.bundle)

			_, err := GenerateConfig(in)
			if err == nil {
				t.Fatal("GenerateConfig accepted a secrets bundle it cannot have generated from")
			}

			// Same rule as every other secret parse: the message must not
			// quote the document, because the document is private keys.
			if strings.Contains(err.Error(), tc.bundle) {
				t.Errorf("the refusal quotes the bundle it was given: %v", err)
			}
		})
	}
}

func TestGenerateConfigPinsInstallerToTheImageVersion(t *testing.T) {
	in := testInput()
	// Deliberately NOT the generator's version: an installer pinned to ours
	// turns a fresh install into a silent cross-version upgrade.
	in.TalosVersion = "v1.12.0"

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	if want := "image: ghcr.io/siderolabs/installer:v1.12.0"; !strings.Contains(doc, want) {
		t.Errorf("install image is not %q\n"+
			"  reason: unset, Talos defaults the installer to the GENERATOR's version and upgrades the node mid-install\n%s",
			want, redact(doc))
	}

	if strings.Contains(doc, "installer:"+GeneratorVersion()) {
		t.Errorf("install image is pinned to the generator version %s\n"+
			"  reason: the installer must follow the ISO, not this binary", GeneratorVersion())
	}
}

var kubeletImage = regexp.MustCompile(`image: ghcr\.io/siderolabs/kubelet:v(\S+)`)

// The Kubernetes version is the installer pin's problem one field over. The
// generator's constants.DefaultKubernetesVersion is a property of the machinery
// this binary was built against, while CheckVersion deliberately admits any
// image at or below the generator — so a v1.12 ISO handed the generator's
// default gets a kubelet outside Talos 1.12's supported window, and finds out
// on the node.
func TestGenerateConfigPinsAKubernetesVersionTheImageSupports(t *testing.T) {
	for _, talosVersion := range []string{"v1.13.7", "v1.12.0", "v1.5.0"} {
		t.Run(talosVersion, func(t *testing.T) {
			in := testInput()
			in.TalosVersion = talosVersion

			doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

			m := kubeletImage.FindStringSubmatch(doc)
			if m == nil {
				t.Fatalf("no kubelet image pinned\n"+
					"  reason: emptyIf() drops the image when the Kubernetes version is empty, so a missing "+
					"version reads as a config that merely omits a field\n%s", redact(doc))
			}

			// machinery is the ORACLE here, deliberately. A table of
			// Talos-to-Kubernetes versions copied into this test is a second
			// copy of the thing that drifts, and it would agree with a wrong
			// implementation as happily as with a right one.
			k8s, err := compatibility.ParseKubernetesVersion(m[1])
			if err != nil {
				t.Fatalf("kubelet is pinned to %q, which is not a Kubernetes version: %s", m[1], redactErr(err))
			}

			target, err := compatibility.ParseTalosVersion(&machineapi.VersionInfo{Tag: talosVersion})
			if err != nil {
				t.Fatalf("parsing Talos version %q: %s", talosVersion, redactErr(err))
			}

			if err := k8s.SupportedWith(target); err != nil {
				t.Errorf("a Talos %s image is handed Kubernetes %s: %s\n"+
					"  reason: the kubelet and every control-plane component are pinned by version in this "+
					"config; the generator's own default belongs to THIS binary, not to the image",
					talosVersion, m[1], redactErr(err))
			}
		})
	}
}

// An image machinery has no compatibility data for cannot be given a
// Kubernetes version at all, and the generator's default is exactly the wrong
// answer — the same silent generator-derived pin, one field over.
func TestGenerateConfigRefusesAnImageWithNoKnownKubernetesVersion(t *testing.T) {
	in := testInput()
	in.TalosVersion = "v1.1.0"

	_, err := GenerateConfig(in)
	if err == nil {
		t.Fatal("generated a config for an image machinery has no Kubernetes compatibility data for\n" +
			"  reason: the only version left to pin is this binary's own, which is the bug the installer pin exists to prevent")
	}

	if !strings.Contains(err.Error(), "v1.1.0") {
		t.Errorf("refusal does not name the image version: %s", redactErr(err))
	}
}

func TestGenerateConfigCarriesConsoleArgToTheInstalledSystem(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	if !regexp.MustCompile(`(?m)^ {8}extraKernelArgs:\n {12}- console=ttyS0$`).MatchString(doc) {
		t.Errorf("install has no extraKernelArgs console=ttyS0\n"+
			"  reason: the installed system writes its OWN cmdline and does not inherit the ISO's console; "+
			"serial goes dead at exactly the boot you need to watch\n%s", redact(doc))
	}

	if regexp.MustCompile(`(?m)^ {8}grubUseUKICmdline: true`).MatchString(doc) {
		t.Errorf("extraKernelArgs is set while GRUB takes its cmdline from the installer's UKI\n" +
			"  reason: the two are mutually exclusive — the console arg is ignored, and the node rejects the config outright")
	}
}

func TestEmptyConsoleArgEmitsNoKernelArgsAndLeavesUKIAlone(t *testing.T) {
	in := testInput()
	in.ConsoleArg = ""

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	if regexp.MustCompile(`(?m)^ {8}extraKernelArgs:`).MatchString(doc) {
		t.Errorf("install emitted extraKernelArgs with no console arg set\n"+
			"  reason: real hardware has a firmware-configured console; forcing one "+
			"derived from the HOST's architecture is how a node boots with a dead "+
			"console\n%s", redact(doc))
	}

	// The UKI switch exists ONLY to stop GRUB ignoring extraKernelArgs. With no
	// extraKernelArgs there is nothing to stop, and flipping it anyway changes a
	// node's boot path for no reason. Anchored to `: false` because the absent
	// case and the explicitly-false case are different facts.
	if regexp.MustCompile(`(?m)^ {8}grubUseUKICmdline: false`).MatchString(doc) {
		t.Errorf("grubUseUKICmdline was forced false with no console arg to protect\n"+
			"  reason: its only purpose is that GRUB's UKI cmdline and extraKernelArgs "+
			"cannot coexist — with no extraKernelArgs there is no conflict\n%s", redact(doc))
	}
}

// NewInput takes clusterName and endpoint adjacently and both are strings, so
// a swap compiles and produces a self-consistent — and useless — cluster.
func TestGenerateConfigNamesTheClusterAndTheEndpointTheRightWayRound(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	// A worker config generates, encodes, validates and carries every install
	// option asserted elsewhere. It just never becomes a cluster: nothing runs
	// etcd, and `talosctl bootstrap` has nothing to bootstrap.
	if !strings.Contains(doc, "type: controlplane") {
		t.Errorf("machine type is not controlplane\n"+
			"  reason: a single-node cluster has exactly one node; if it is a worker there is no control plane at all\n%s", redact(doc))
	}

	if !strings.Contains(doc, "clusterName: probe") {
		t.Errorf("cluster is not named probe\n"+
			"  reason: cluster name and endpoint are adjacent string arguments; swapped, everything still generates\n%s", redact(doc))
	}

	if !strings.Contains(doc, "endpoint: https://127.0.0.1:6443") {
		t.Errorf("control plane endpoint is not the Kubernetes API URL\n"+
			"  reason: the node would join a cluster whose API address is its own name\n%s", redact(doc))
	}

	// emptyIf() silently drops the kubelet image when the Kubernetes version is
	// empty, so a missing version reads as a config that merely omits a field.
	if !strings.Contains(doc, "image: ghcr.io/siderolabs/kubelet:v") {
		t.Errorf("kubelet image is not pinned\n"+
			"  reason: an empty Kubernetes version leaves the node without a kubelet to run\n%s", redact(doc))
	}
}

func TestGenerateConfigSchedulesOnTheControlPlane(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	if !strings.Contains(doc, "allowSchedulingOnControlPlanes: true") {
		t.Errorf("control-plane taint is left in place\n"+
			"  reason: a single-node cluster schedules NOTHING while the taint stands; this is a topology correction\n%s", redact(doc))
	}
}

func TestCertSANComesFromAPIAddress(t *testing.T) {
	// Both arms matter. 127.0.0.1 is the QEMU regression — the generated config
	// must not change. 192.168.1.50 is the one that was IMPOSSIBLE before this
	// task and is the whole reason for it.
	//
	// mustGenerate rather than mustGenerateDefault: a non-default input cannot
	// use the shared CA set, so this pays for two full generations. That is the
	// price of proving the address is threaded rather than hardcoded.
	for _, addr := range []string{"127.0.0.1", "192.168.1.50"} {
		in := testInput()
		in.APIAddress = addr

		cfg, err := configloader.NewFromBytes(mustGenerate(t, in).ControlPlane)
		if err != nil {
			t.Fatalf("generated config does not parse: %s", redactErr(err))
		}

		// Asserted through the TYPED API on purpose, exactly as the test this
		// replaces did: the address also appears under apiServer.certSANs,
		// where the endpoint puts it for free, so a substring match would pass
		// with the machine SAN missing entirely.
		if sans := cfg.Machine().Security().CertSANs(); !slices.Contains(sans, addr) {
			t.Errorf("machine certSANs = %v, want %s\n"+
				"  reason: the cert must name the address the CLIENT DIALS, or every "+
				"authenticated call fails the TLS handshake", sans, addr)
		}
	}
}

func TestGenerateConfigRefusesAnEmptyAPIAddress(t *testing.T) {
	in := testInput()
	in.APIAddress = ""

	if _, err := GenerateConfig(in); err == nil {
		t.Error("GenerateConfig accepted an empty APIAddress\n" +
			"  reason: an empty SAN list yields a cert naming nothing, which fails at " +
			"the handshake minutes later rather than here")
	}
}

func TestGenerateConfigCreatesUserVolumeOnTheDataDisk(t *testing.T) {
	cp := mustGenerateDefault(t).ControlPlane

	vol, ok := docOfKindT(t, cp, "UserVolumeConfig")
	if !ok {
		t.Fatalf("no UserVolumeConfig document\n"+
			"  reason: PVCs would land on EPHEMERAL beside etcd, where a runaway PVC wedges the only control-plane node\n%s", redact(string(cp)))
	}

	if !strings.Contains(vol, "name: local-path-provisioner") {
		t.Errorf("user volume is not named local-path-provisioner\n"+
			"  reason: the name fixes the mount path /var/mnt/<name>, which the provisioner manifest hardcodes\n%s", redact(vol))
	}

	if !strings.Contains(vol, `disk.serial == "talos-data"`) {
		t.Errorf("user volume does not select the data disk by serial\n"+
			"  reason: any other matcher can pick the system disk or the boot ISO, both of which are also virtio-blk\n%s", redact(vol))
	}

	if !strings.Contains(vol, "volumeType: partition") {
		t.Errorf("user volume has no explicit volumeType\n"+
			"  reason: the shape of the volume is then a runtime default this config does not state\n%s", redact(vol))
	}

	if !strings.Contains(vol, "grow: true") {
		t.Errorf("user volume does not grow to the disk\n"+
			"  reason: it would sit at its minimum size and a 40Gi data disk would silently provide 1Gi of PVCs\n%s", redact(vol))
	}

	if !strings.Contains(vol, "type: xfs") {
		t.Errorf("user volume has no filesystem\n"+
			"  reason: an unformatted volume validates fine and then holds nothing\n%s", redact(vol))
	}

	if strings.Contains(vol, "talos-system") {
		t.Errorf("user volume mentions the system disk serial\n"+
			"  reason: provisioning a user volume on the install target destroys it\n%s", redact(vol))
	}
}

func TestGenerateConfigOmitsUserVolumeWithoutDataDisk(t *testing.T) {
	in := testInput()
	in.DataDiskSerial = ""

	cp := mustGenerate(t, in).ControlPlane

	if _, ok := docOfKindT(t, cp, "UserVolumeConfig"); ok {
		t.Errorf("user volume emitted with no data disk\n"+
			"  reason: the volume would wait forever for a disk that was never attached, and the node never reaches ready\n%s", redact(string(cp)))
	}

	if strings.Contains(string(cp), "talos-data") {
		t.Error("no data disk means no reference to one; the two halves of storage must not disagree")
	}
}

func TestGenerateConfigRefusesAnImageNewerThanTheGenerator(t *testing.T) {
	in := testInput()
	in.TalosVersion = "v1.99.0"

	if _, err := GenerateConfig(in); err == nil {
		t.Fatal("generated a config for an image newer than the generator\n" +
			"  reason: exceeding the contract does not error, it silently emits a config for a Talos that does not exist")
	}
}

// An unknown image version disables the version GUARD by design (Task 2) — the
// guard only refuses images it can prove are too new. Generation is stricter,
// and has to be: the installer tag is written to disk, and defaulting it to
// ours is the cross-version install the pin above exists to prevent, rebuilt by
// hand for the one image we could not identify.
func TestGenerateConfigRefusesAnUnknownImageVersion(t *testing.T) {
	in := testInput()
	in.TalosVersion = ""

	_, err := GenerateConfig(in)
	if err == nil {
		t.Fatal("generated a config for an image of unknown version\n" +
			"  reason: the installer tag can only be this binary's version, which either the maintenance system " +
			"rejects or installs into a node that hangs at /sbin/init")
	}

	// A refusal with no way out is a dead end. The stock ISO's volume id is
	// where a usable version comes from, so the message has to name it.
	if !strings.Contains(err.Error(), "TALOS_V") {
		t.Errorf("refusal does not say how to obtain an identifiable image: %s", redactErr(err))
	}
}

func TestGenerateConfigTargetsTheRequestedContract(t *testing.T) {
	oldIn, newIn := testInput(), testInput()
	oldIn.TalosVersion, newIn.TalosVersion = "v1.5.0", "v1.13.7"

	old := code(string(mustGenerate(t, oldIn).ControlPlane))
	current := code(string(mustGenerate(t, newIn).ControlPlane))

	// v1.5 predates KubePrism; v1.13 has it. Identical output for both means
	// the contract is not reaching the generator at all.
	if strings.Contains(old, "kubePrism") {
		t.Error("a v1.5 contract emitted kubePrism\n" +
			"  reason: the node rejects fields its version does not know")
	}

	if !strings.Contains(current, "kubePrism") {
		t.Error("a v1.13 contract did not emit kubePrism\n" +
			"  reason: the contract is not being threaded through; every version-gated default is then wrong")
	}

	// The install-time override below is version-gated too: grubUseUKICmdline
	// did not exist before 1.12, and Talos rejects fields it does not know.
	if strings.Contains(old, "grubUseUKICmdline") {
		t.Error("a v1.5 contract emitted grubUseUKICmdline\n" +
			"  reason: an override must not reintroduce a field the contract deliberately withheld")
	}
}

// BOTH PATHS, because machinery is what decides whether either one boots.
//
// The static arm is a guard rather than a live defect: v1alpha1.NetworkConfig's
// fields are already marked Deprecated in machinery v1.13.7, and a bump that
// turned deprecation into rejection would otherwise surface on a real node
// mid-boot — the unrepairable failure this whole block exists to prevent —
// instead of here. The DHCP arm is every machine that existed before it.
func TestGenerateConfigProducesAConfigMachineryAcceptsBack(t *testing.T) {
	accepted := func(t *testing.T, cp []byte) {
		t.Helper()

		cfg, err := configloader.NewFromBytes(cp)
		if err != nil {
			t.Fatalf("generated config does not parse: %s\n"+
				"  reason: an unparseable config is discovered by the NODE, minutes into a boot", redactErr(err))
		}

		warnings, err := cfg.Validate(metalMode{})
		if err != nil {
			t.Fatalf("generated config does not validate: %s", redactErr(err))
		}

		// Logged on the PASSING path too, so this is the one line in the
		// package that prints on every run — the last place a raw secret
		// should reach.
		t.Logf("validation warnings: %s", redact(fmt.Sprint(warnings)))
	}

	t.Run("dhcp", func(t *testing.T) {
		accepted(t, mustGenerateDefault(t).ControlPlane)
	})

	t.Run("static", func(t *testing.T) {
		in := testInput()
		in.Network = testNetwork()

		accepted(t, mustGenerate(t, in).ControlPlane)
	})
}

func TestGenerateConfigProducesATalosconfigPointingAtTheHostForward(t *testing.T) {
	g := mustGenerateDefault(t)

	c, err := clientconfig.FromBytes(g.Talosconfig)
	if err != nil {
		t.Fatalf("talosconfig does not parse: %s", redactErr(err))
	}

	ctx, ok := c.Contexts[c.Context]
	if !ok {
		t.Fatalf("talosconfig has no context %q", c.Context)
	}

	if c.Context != "probe" {
		t.Errorf("talosconfig context = %q, want the cluster name\n"+
			"  reason: the context is named after the cluster; anything else means the name and the endpoint were swapped", c.Context)
	}

	if !slices.Contains(ctx.Endpoints, "127.0.0.1") {
		t.Errorf("talosconfig endpoints = %v, want 127.0.0.1\n"+
			"  reason: an endpointless talosconfig makes every talosctl call require -e, including the bootstrap", ctx.Endpoints)
	}
}

// secrets.yaml exists so the cluster can be regenerated with the same identity
// (`talosctl gen config --with-secrets`). That is worth nothing if machinery
// cannot read back what we wrote.
func TestGenerateConfigProducesReloadableSecrets(t *testing.T) {
	g := mustGenerateDefault(t)

	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, g.Secrets, 0o600); err != nil {
		t.Fatal(err)
	}

	bundle, err := secrets.LoadBundle(path)
	if err != nil {
		t.Fatalf("machinery cannot load the secrets we wrote: %s", redactErr(err))
	}

	if err := bundle.Validate(); err != nil {
		t.Errorf("reloaded secrets bundle is incomplete: %s\n"+
			"  reason: a bundle that loads but is missing a CA regenerates a cluster the old certs cannot talk to", redactErr(err))
	}
}

// leafStrings collects every scalar string in a decoded YAML tree.
func leafStrings(node any, into *[]string) {
	switch v := node.(type) {
	case map[string]any:
		for _, child := range v {
			leafStrings(child, into)
		}
	case []any:
		for _, child := range v {
			leafStrings(child, into)
		}
	case string:
		*into = append(*into, v)
	}
}

// maxSurvivingRun is the longest fragment of a secret that may remain in a
// redacted artifact.
//
// Whole-value containment is not a verdict. A redactor that clips ONE
// character off a 44-character private key leaves 43 of them in the output and
// scores as safe, so the assertion is on the longest surviving RUN instead.
// Sixteen characters of base64 is 96 bits; nothing structural in these
// documents — indentation, keys, image references, `<redacted N chars>` —
// collides with that by accident.
const maxSurvivingRun = 16

// survivingRun returns a fragment of secret that is still present in text, or
// "" if none is. The window is capped at the secret's own length so that
// lowering shortestSecret cannot silently disable the guard.
func survivingRun(text, secret string) string {
	n := min(maxSurvivingRun, len(secret))

	for i := 0; i+n <= len(secret); i++ {
		if run := secret[i : i+n]; strings.Contains(text, run) {
			return run
		}
	}

	return ""
}

// twinnable is the length above which a secret is also checked as the value
// machinery could equally have drawn — see twinAlphabet.
//
// Only long values qualify. Below 40 characters the shape in this bundle is a
// bootstrap token, `abc123.0123456789abcdef`, and a `-` in the middle of one
// is not a value machinery can produce; twinning it would fail the guard
// against a redactor that is correct.
const twinnable = 40

// twinAlphabet forces one alphabet-distinguishing character into the middle of
// v.
//
// A bundle is ONE random draw, which makes a guard that only sees that draw a
// coin flip. Whether a 44-character base64url secret happens to contain `-` or
// `_` is chance — about a quarter of the time it contains neither — so a
// redactor covering only the standard `+/` alphabet passes against roughly one
// bundle in four. That is not a hypothetical: reverting the base64 class to
// `[A-Za-z0-9+/]{40,}`, the exact leak this shape exists to close, failed 6 of
// 8 runs and passed 2.
//
// Twinning removes the draw from the verdict. Whatever machinery produced, the
// redactor is also handed the same value carrying `+`, `/`, `-` and `_` in
// turn, so a class that covers only one alphabet fails every time.
func twinAlphabet(v string, c byte) string {
	mid := len(v) / 2

	return v[:mid] + string(c) + v[mid+1:]
}

// The guard that keeps redact() honest. It does not check redact() against a
// list of field names — that list is exactly what drifts. It takes the secrets
// bundle as GROUND TRUTH: every string machinery put in it is by definition a
// secret, and none of them may survive redact() of any artifact. A secret
// added by a future machinery therefore fails HERE, in one place, instead of
// appearing in someone's CI log.
func TestRedactHidesEveryGeneratedSecret(t *testing.T) {
	g := mustGenerateDefault(t)

	var bundle map[string]any
	if err := yaml.Unmarshal(g.Secrets, &bundle); err != nil {
		t.Fatalf("secrets bundle does not decode: %s", redactErr(err))
	}

	var values []string

	leafStrings(bundle, &values)

	// Short strings are labels, not secrets: the bundle carries a few
	// ("v1alpha1"), and the shortest real secret in it is the 23-character
	// bootstrap token.
	const shortestSecret = 20

	// A bundle with no twinnable value would leave the alphabet half of this
	// guard asserting nothing at all.
	twins := 0

	var secretValues []string

	for _, v := range values {
		if len(v) >= shortestSecret {
			secretValues = append(secretValues, v)
		}

		if len(v) >= twinnable {
			twins++
		}
	}

	if len(secretValues) < 10 {
		t.Fatalf("only %d secret values found in the bundle; the guard is not looking at anything",
			len(secretValues))
	}

	if twins == 0 {
		t.Fatal("no secret long enough to twin; the alphabet half of this guard is asserting nothing")
	}

	for _, artifact := range []struct {
		name  string
		bytes []byte
	}{
		{"ControlPlane", g.ControlPlane},
		{"Talosconfig", g.Talosconfig},
		{"Secrets", g.Secrets},
	} {
		asIs := redact(string(artifact.bytes))

		for _, secret := range secretValues {
			// The secret itself is NOT printed, for the reason this whole test
			// exists — only its length and how much of it got through.
			if run := survivingRun(asIs, secret); run != "" {
				t.Errorf("redact() left %d of the %d characters of a secret in %s\n"+
					"  reason: every dump in this file goes through redact(); a shape it does not "+
					"cover reaches terminals, CI logs and pasted bug reports", len(run), len(secret), artifact.name)
			}
		}

		// Same artifact, same structure, but with every long secret rewritten
		// into a value the same generator could have produced instead. One
		// pass per alphabet character rather than one per secret: the verdict
		// is the same and the artifact is only redacted four more times.
		for _, c := range []byte{'+', '/', '-', '_'} {
			text := string(artifact.bytes)
			twinned := make([]string, 0, twins)

			for _, secret := range secretValues {
				if len(secret) < twinnable {
					continue
				}

				twin := twinAlphabet(secret, c)
				text = strings.ReplaceAll(text, secret, twin)
				twinned = append(twinned, twin)
			}

			redacted := redact(text)

			for _, twin := range twinned {
				if run := survivingRun(redacted, twin); run != "" {
					t.Errorf("redact() left %d of the %d characters of a %q-alphabet secret in %s\n"+
						"  reason: which alphabet a generated secret lands in is chance; a redactor that "+
						"covers only one of them leaks whenever the draw goes the other way", len(run), len(twin), string(c), artifact.name)
				}
			}
		}

		if strings.Contains(asIs, "-----BEGIN") {
			t.Errorf("redact() left a PEM block in %s", artifact.name)
		}
	}
}

// A redactor with no test that it PRESERVES anything can be `return ""` and
// still pass the test above. These are the values the dumps exist to show.
func TestRedactKeepsTheValuesTheAssertionsAreAbout(t *testing.T) {
	redacted := redact(string(mustGenerateDefault(t).ControlPlane))

	for _, want := range []string{
		"serial: talos-system",
		"image: ghcr.io/siderolabs/installer:v1.13.7",
		"- console=ttyS0",
		"type: controlplane",
		"clusterName: probe",
		"endpoint: https://127.0.0.1:6443",
		"allowSchedulingOnControlPlanes: true",
		"name: local-path-provisioner",
		`disk.serial == "talos-data"`,
		"volumeType: partition",
		"grow: true",
		"type: xfs",
	} {
		if !strings.Contains(redacted, want) {
			t.Errorf("redact() removed %q\n"+
				"  reason: over-broad redaction leaves a failing assertion with nothing to diagnose from, "+
				"which is the only reason the dumps were kept at all", want)
		}
	}
}

// metalMode is the validation mode of a machine that installs to a disk, which
// is the only mode tinq ever produces configs for.
type metalMode struct{}

func (metalMode) String() string        { return "metal" }
func (metalMode) RequiresInstall() bool { return true }
func (metalMode) InContainer() bool     { return false }

// ── the arm64 kexec workaround ──────────────────────────────────────────────
//
// Talos kexecs into the installed kernel instead of rebooting through firmware.
// Under QEMU on macOS that path dies in the guest, so `-up` asks the node to
// skip it. The sysctl is what upstream's own `talosctl cluster create` sets, and
// it lands on the ISO's RUNNING kernel because Talos applies machine-config
// sysctls in maintenance mode — before the install, and therefore before the
// reboot it has to change. See docs/kexec-on-arm64-macos.md.

// kexecSysctl matches the sysctl inside the machine's sysctls map. The pairing
// matters: `kernel.kexec_load_disabled` under some other key proves nothing.
var kexecSysctl = regexp.MustCompile(`(?m)^ {4}sysctls:\n(?: {8}\S+: .*\n)* {8}kernel\.kexec_load_disabled: (\S+)`)

func TestGenerateConfigDisablesKexecWhenAsked(t *testing.T) {
	in := testInput()
	in.DisableKexec = true

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	m := kexecSysctl.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("no kernel.kexec_load_disabled sysctl\n"+
			"  reason: without it Talos kexecs on reboot, and under QEMU on macOS the guest dies\n"+
			"  there — the node never boots what it just installed\n%s", redact(doc))
	}

	// Talos wants the STRING "1"; a bare 1 is an int in YAML and the sysctls
	// map is map[string]string, so an unquoted value does not decode.
	if m[1] != `"1"` {
		t.Errorf("kernel.kexec_load_disabled = %s, want %q\n"+
			"  reason: sysctls is map[string]string — an unquoted 1 is an int and fails to decode", m[1], `"1"`)
	}
}

// Kexec is a FEATURE where it works: it skips a whole firmware boot. Linux/KVM
// is unaffected by the bug, so disabling it there would be a permanent tax paid
// for someone else's platform.
func TestGenerateConfigLeavesKexecAloneByDefault(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	if strings.Contains(doc, "kexec_load_disabled") {
		t.Errorf("kexec was disabled without being asked\n"+
			"  reason: kexec works on Linux/KVM and saves a firmware boot; the workaround is\n"+
			"  for the hosts that need it, not for everyone\n%s", redact(doc))
	}
}

// testNetwork is the block the target machine uses. Its values are deliberately
// unlike anything else in this file: a fixture that reused 127.0.0.1 could pass
// on a config that carried the loopback endpoint and no network at all.
func testNetwork() *Network {
	return &Network{
		Address:      "192.168.2.10/24",
		Gateway:      "192.168.2.1",
		Nameservers:  []string{"1.1.1.1"},
		HardwareAddr: "84:47:09:47:35:f9",
	}
}

// EVERY assertion here is against v1alpha1Doc, never the raw bytes. Machinery's
// encoder emits commented-out examples, several of which mention hardwareAddr
// and addresses, so a Contains against the raw config matches a comment and
// reports a field that was never set.
func TestGenerateConfigWritesTheStaticNetwork(t *testing.T) {
	in := testInput()
	in.Network = testNetwork()

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	for _, want := range []string{
		"hardwareAddr: 84:47:09:47:35:f9",
		"192.168.2.10/24",
		"gateway: 192.168.2.1",
		"1.1.1.1",
		"dhcp: false",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the generated config does not carry %q\n"+
				"  reason: the installed system writes its own kernel cmdline and inherits\n"+
				"  nothing from the ISO, so an address that is not in this config is gone\n"+
				"  the moment the node reboots", want)
		}
	}

	// The DEFAULT ROUTE, not merely a gateway value. A gateway on a route to
	// some other network reads identically field by field and leaves the node
	// with no way off its segment.
	if !defaultRoute.MatchString(doc) {
		t.Errorf("no default route through the gateway:\n%s", redact(doc))
	}
}

// defaultRoute matches a route whose destination is everything. The pairing is
// the point: `gateway:` anywhere in the file proves nothing about which
// destination it serves.
var defaultRoute = regexp.MustCompile(`network: 0\.0\.0\.0/0\n\s+gateway: 192\.168\.2\.1`)

// REQUIREMENT 2, and the regression target for every machine that existed
// before this feature. Absent means DHCP, which means machinery's own defaults
// and not one byte from this branch.
func TestGenerateConfigEmitsNoNetworkWithoutABlock(t *testing.T) {
	doc := v1alpha1Doc(t, mustGenerateDefault(t).ControlPlane)

	// Three markers that can ONLY come from networkOption. A `network:` key by
	// itself is machinery's, and asserting on that would fail for a reason
	// this branch never caused.
	for _, never := range []string{"hardwareAddr:", "dhcp: false", "0.0.0.0/0"} {
		if strings.Contains(doc, never) {
			t.Errorf("a machine with no network block still got %q in its config\n"+
				"  reason: every QEMU machine and every DHCP node takes this path, and a\n"+
				"  static interface appearing in it is a node that stops answering", never)
		}
	}
}

// A config patch is machinery's own supported override — the same strategic-merge
// shape `talosctl --config-patch` and talhelper accept — applied LAST, over
// everything tinq generated. The motivating case is machine.network.nameservers
// on the DHCP dev VM: the static Network block cannot set nameservers without
// also inventing an address and gateway, but a one-line patch can, which is how
// the dev cluster is pointed at the seed's DNS to resolve *.lab.
func TestGenerateConfigAppliesAConfigPatch(t *testing.T) {
	in := testInput()
	in.ConfigPatches = []string{
		"machine:\n  network:\n    nameservers:\n      - 192.168.122.10\n",
	}

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	if !strings.Contains(doc, "192.168.122.10") {
		t.Errorf("the patched nameserver is not in the generated config\n"+
			"  reason: a config patch is the only way to set machine.network.nameservers\n"+
			"  on the DHCP dev VM, and without it the dev cluster cannot resolve *.lab from\n"+
			"  the seed the way the metal nodes already do\n%s", redact(doc))
	}
}

// A patch overrides what tinq itself set, because it is applied AFTER the
// package's own PatchV1Alpha1. Proven against the disk selector — install by
// serial is tinq's, and a patch that flips it to a device path must win.
func TestGenerateConfigConfigPatchOverridesGeneratedFields(t *testing.T) {
	in := testInput()
	in.ConfigPatches = []string{
		"machine:\n  install:\n    disk: /dev/patched\n",
	}

	doc := v1alpha1Doc(t, mustGenerate(t, in).ControlPlane)

	if !strings.Contains(doc, "/dev/patched") {
		t.Errorf("the patch did not override the generated install section\n"+
			"  reason: patches are the last writer; if tinq's own PatchV1Alpha1 wins\n"+
			"  instead, a machine file cannot correct anything tinq generated\n%s", redact(doc))
	}
}

// An unparseable patch is refused at GENERATION, on the workstation, not carried
// to a node that then rejects it minutes after it has already installed.
func TestGenerateConfigRejectsABadConfigPatch(t *testing.T) {
	in := testInput()
	in.ConfigPatches = []string{"this: is: not: valid: yaml\n"}

	if _, err := GenerateConfig(in); err == nil {
		t.Error("GenerateConfig accepted an unparseable config patch\n" +
			"  reason: a patch that cannot be parsed must fail here, where the operator\n" +
			"  sees it, not on a booted node where it reads as a broken cluster")
	}
}
