package cluster

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v4"

	machineapi "github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/cel"
	"github.com/siderolabs/talos/pkg/machinery/cel/celenv"
	"github.com/siderolabs/talos/pkg/machinery/compatibility"
	"github.com/siderolabs/talos/pkg/machinery/config"
	// The DOCUMENT interface lives in machinery's inner config/config package,
	// not the outer one already imported above as `config`. Aliased rather than
	// renaming that import, which is used for ParseContractFromVersion and has
	// nothing to do with documents.
	coreconfig "github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/configpatcher"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	"github.com/siderolabs/talos/pkg/machinery/config/generate"
	"github.com/siderolabs/talos/pkg/machinery/config/generate/secrets"
	"github.com/siderolabs/talos/pkg/machinery/config/machine"
	"github.com/siderolabs/talos/pkg/machinery/config/types/block"
	v1alpha1 "github.com/siderolabs/talos/pkg/machinery/config/types/v1alpha1"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	blockres "github.com/siderolabs/talos/pkg/machinery/resources/block"
)

// RegistryMirror redirects one registry host to one endpoint, so the cluster
// can pull images that exist nowhere on the internet.
//
// It is FLAT — one host, one endpoint — while Talos's own shape is a map of
// host to a list of endpoints. The fold happens in registriesConfig, in one
// place, because the CRD publishes a list to stay shaped like hostForwards
// beside it and a contract that mixes list and map for the same kind of thing
// is one nobody can predict.
type RegistryMirror struct {
	// Host is the first segment of an image reference, INCLUDING the port.
	// "10.0.2.2:5000/app:v1" is looked up under "10.0.2.2:5000"; the bare host
	// never matches it, and the failure is a pull from the real internet.
	Host string
	// Endpoint is the mirror URL. The SCHEME is the plain-HTTP switch: http://
	// makes containerd speak cleartext, and no boolean anywhere does that job.
	Endpoint string
	// CA is a PEM certificate bundle to verify an https:// endpoint against,
	// emitted as machine.registries.config.<host>.tls.ca. It is how a node
	// trusts a registry with a PRIVATE CA (the seed's step-ca) without the
	// blunt instrument of InsecureSkipVerify. Empty for http:// or a
	// publicly-trusted endpoint.
	CA string
	// InsecureSkipVerify stops certificate verification for an https://
	// endpoint. Meaningless for http://, where there is no certificate.
	InsecureSkipVerify bool
	// OverridePath uses the endpoint path verbatim instead of appending /v2/.
	OverridePath bool
}

// ConfigInput is everything the generated machine config depends on that this
// package cannot know for itself.
//
// The two serials are INPUTS rather than constants because they are set on the
// QEMU devices by package main, which cannot be imported from here. Copying the
// literals across the boundary would compile, read correctly, and drift the
// first time either side is renamed — after which the install selector matches
// no disk and Talos installs nowhere, with nothing pointing at the cause.
type ConfigInput struct {
	ClusterName string
	// Endpoint is the Kubernetes API endpoint, e.g. https://127.0.0.1:6443.
	Endpoint string
	// APIAddress is the address a CLIENT DIALS to reach this machine, with no
	// port — it becomes both the apid certificate's subject alt name and the
	// talosconfig's endpoint.
	//
	// It is DERIVED from the Talos endpoint by the caller (see up.go's
	// apiAddress) rather than configured beside it. The certificate must name
	// what the client dials, and the endpoint IS what the client dials; two
	// independent fields could be set to disagree, and the failure is a TLS
	// handshake error that says nothing about the config that caused it.
	//
	// Under QEMU this is the loopback host side of a port forward. On hardware
	// it is the node's own address. The generated config is identical either
	// way, which is the whole point.
	APIAddress string
	// TalosVersion is the node's Talos version, resolved by the caller from
	// whichever source that substrate has: the ISO's volume id before a VM
	// boots (InspectImageVersion), or the node itself once it is answering in
	// maintenance mode (NodeVersion). It is REQUIRED: both sources render an
	// unidentifiable answer as "", and GenerateConfig refuses that rather than
	// substituting its own version, because this value becomes the installer
	// image tag on the node's disk.
	TalosVersion string
	// ConsoleArg is the console kernel argument for the NODE, or "" for none.
	//
	// EMPTY IS AN ANSWER, not an unset field, and two gates below read it as
	// one: with "" no extraKernelArgs is emitted at all, and
	// InstallGrubUseUKICmdline is left exactly as machinery set it. The two
	// move together because they are one decision — GRUB's UKI cmdline and
	// extraKernelArgs cannot coexist, so switching the UKI cmdline off is only
	// justified by an argument actually being passed.
	//
	// Under QEMU the console is the only way to watch a boot and the installed
	// system inherits nothing from the ISO, so one has to be named. On hardware
	// the firmware has already configured a console and there is usually a
	// display, so naming one is a guess that can boot the node with a dead
	// console. The CALLER decides which case it is in; this package cannot
	// know, and no longer has a way to ask.
	ConsoleArg string
	// SystemDisk names the install target, by serial or by WWID.
	//
	// A DiskRef where DataDiskSerial below is a bare string, and the asymmetry
	// is the actual capability rather than an oversight: the install target is
	// the one disk a caller may be UNABLE to name by serial, because a USB
	// bridge often reports none and refusing that would refuse the machine. A
	// data disk is chosen from what is left, and every path that has one today
	// picks a disk with a serial.
	SystemDisk DiskRef
	// DataDiskSerial is the serial of the PVC disk. Empty means there is no
	// SEPARATE data disk — see EphemeralMaxSize for the other way to get a
	// user volume, and note that with neither, no user volume is emitted.
	DataDiskSerial string
	// EphemeralMaxSize caps Talos's EPHEMERAL volume so the user volume can
	// have the REST OF THE SAME DISK. Empty means EPHEMERAL is left alone.
	//
	// It exists for a single-disk machine. EPHEMERAL is where /var lives —
	// etcd, container images, kubelet state — and machinery documents that a
	// volume with no maxSize "can grow to the size of the disk", so by default
	// it takes everything and there is no free space a user volume could be
	// cut from. Capping it is what creates that space.
	//
	// WHAT IT BUYS IS ONE PROPERTY, and it is worth being exact because the
	// two-disk case buys three: a PVC that runs away hits the user volume's
	// partition boundary instead of filling /var and taking etcd down with it.
	// It does NOT isolate I/O and it does NOT survive the disk dying, because
	// it is the same disk. Anyone reaching for this on a machine that HAS a
	// second disk should use the second disk.
	//
	// SET AT INSTALL TIME AND ONLY THEN. Partition sizes are not renegotiated
	// on a running node, so a value that turns out wrong costs a wipe and a
	// reinstall — which is why it is an explicit field and not a default.
	EphemeralMaxSize string
	// InstallerImage overrides the installer image, which is otherwise pinned
	// to the ISO's own version. Empty keeps that default.
	//
	// A FIRST-CLASS FIELD rather than something a caller patches in, because
	// machine.install is this generator's own subtree: it sets the disk
	// selector and the UKI cmdline flag there. A strategic merge over the same
	// subtree afterwards damages it -- observed emitting "wipe: null" and
	// producing a node that applies its config, never installs, and never
	// reboots, with nothing on the console to say why. JSON6902 is not an
	// escape hatch either: machinery refuses it for multi-document configs,
	// which any RAIDArrayConfig/UserVolumeConfig setup is.
	InstallerImage string
	// DisableKexec asks the node not to kexec when it reboots, via
	// kernel.kexec_load_disabled. It exists for ONE host platform — QEMU on
	// macOS, where the kexec path dies in the guest on arm64 — and the caller
	// decides, because whether the host is affected is a fact about the host
	// and this package does not know one from another.
	//
	// It is a bool rather than a GOOS because the config layer has no business
	// mapping operating systems to workarounds — and neither does up.go, which
	// stopped holding a platform when cluster/ stopped importing one.
	// cmd/tinq's upOptions makes that call, from the host it detected.
	DisableKexec bool
	// Network is the node's static addressing, or nil for DHCP.
	//
	// NIL IS A REAL ANSWER, not a missing field: with nil, no machine.network
	// section is emitted at all and the node behaves exactly as every machine
	// did before this field existed.
	//
	// Its address is NOT the same question as APIAddress, and the caller is
	// what resolves one to the other. This package is handed the address a
	// client dials; whether that address came from a static block or from the
	// endpoint the node already answers on is the caller's knowledge.
	Network *Network
	// Registries are image registry mirrors. Empty means the node pulls only
	// from upstream, which is the correct default: a mirror that is not
	// running turns every image pull into a timeout, so one is configured only
	// when the caller knows there is something at the other end.
	Registries []RegistryMirror
	// ConfigPatches are machinery config patches applied LAST, over everything
	// this package generated — the same strategic-merge or JSON6902 shape that
	// `talosctl --config-patch` and talhelper accept. Empty means no patch and a
	// byte-identical config to before the field existed.
	//
	// It is the escape hatch for machine-config fields tinq has no dedicated knob
	// for. The motivating one is machine.network.nameservers on the DHCP dev VM:
	// the Network block above cannot set nameservers without also inventing a
	// static address and gateway, but a one-line patch can — which is how the dev
	// cluster is pointed at the seed's DNS so it resolves *.lab the way the metal
	// nodes already do.
	//
	// Applied after our own PatchV1Alpha1 and the volume documents on purpose:
	// last writer wins, so a patch can override anything, and a bad patch fails
	// generation here rather than on a node that already booted.
	ConfigPatches []string
	// SecretsBundle is an EXISTING secrets.yaml to generate against, or nil to
	// mint a fresh one.
	//
	// NIL IS THE BOOTSTRAP CASE and non-nil is the only way to regenerate a
	// config for a node that already exists. A fresh bundle is five new
	// certificate authorities and a new machine token: the node would reject
	// the config as signed by a CA it does not trust, and the talosconfig
	// beside it could not authenticate to the node it was generated for. There
	// is no way back from that on hardware, because the node never serves the
	// maintenance API again.
	//
	// It is BYTES rather than a *secrets.Bundle so callers keep handling it as
	// the opaque secret it is — read from the state dir, passed through, never
	// inspected. It is SECRET and is neither logged nor placed in an error.
	SecretsBundle []byte
}

// Generated holds the three artifacts bring-up needs. All three contain
// secrets; none of them is safe to log.
type Generated struct {
	ControlPlane []byte
	Talosconfig  []byte
	Secrets      []byte
}

// userVolumeName fixes the mount point at /var/mnt/local-path-provisioner,
// which is the root path local-path-provisioner is patched to use. Talos's root
// filesystem is read-only, so the manifest's stock /opt path cannot work; the
// two must agree, and this constant is the agreement.
const userVolumeName = "local-path-provisioner"

// ephemeralFloor is the smallest EPHEMERAL cap ephemeralCap will accept, and it
// is a TYPO DETECTOR rather than a recommendation — a real one wants tens of
// gigabytes. 1 GiB is simply below anything a working node could use, so
// refusing under it cannot refuse a deliberate choice.
const ephemeralFloor = 1 << 30

// errUnknownTalosVersion is the refusal for an image whose Talos version could
// not be determined.
//
// It is ONE function because TWO callers refuse the same condition, and they
// must not drift into two different explanations of it. GenerateConfig refuses
// unconditionally — that is the refusal nothing can bypass. Up refuses at step
// 3, from the ISO alone, BEFORE it boots anything: the outcome is already
// provable there, and reaching this failure through GenerateConfig instead
// costs a booted VM, a state dir and a five-minute maintenance wait for a
// verdict the ISO's volume id gave for free.
func errUnknownTalosVersion() error {
	return fmt.Errorf(`could not determine the Talos version of this image

The installer image is pinned to the IMAGE's own version and cannot be guessed.
Left to default, Talos substitutes the config generator's version (%s), and a
fresh install silently becomes a cross-version upgrade: the maintenance system
already running either rejects the config outright as too new, or accepts it,
installs, and then hangs at /sbin/init with nothing on the console to say why.

  boot a stock Talos ISO, whose volume id encodes the version (e.g. TALOS_V1_13_7)`,
		GeneratorVersion())
}

// GenerateConfig produces the machine config, client config and secrets bundle
// for a single-node cluster.
//
// It is bootstrap only: the output describes a machine that does not exist yet.
// Nothing here reconciles a running one.
func GenerateConfig(in ConfigInput) (*Generated, error) {
	version := in.TalosVersion

	// An unknown version DISABLES the guard (CheckVersion returns false, nil)
	// but must not be generated through. The two are not in tension: the guard
	// asks "may we generate at all", and refuses only images it can prove are
	// too new; the installer tag is a value that gets WRITTEN TO DISK, and
	// there is no safe value to write for an image nobody identified.
	// Substituting GeneratorVersion() here would hand-roll the exact default
	// the pin below exists to override.
	if version == "" {
		return nil, errUnknownTalosVersion()
	}

	// Refused here rather than at the handshake. An empty SAN list produces a
	// certificate that names nothing; the node installs, boots, serves apid,
	// and every authenticated call then fails minutes later with an error
	// about certificates and nothing pointing at this field.
	if in.APIAddress == "" {
		return nil, errors.New("no API address: this is the address a client dials to reach " +
			"the node, and it must be in apid's certificate or no authenticated call can " +
			"ever succeed")
	}

	// checked is deliberately discarded, and there are TWO ways it comes back
	// false — the comment has to cover both, because "ignoring this costs
	// something visible" was the whole reason for the second return value.
	//
	// (1) An unparseable IMAGE version. The only one InspectImageVersion
	// produces is "", refused above; anything else reaches
	// ParseContractFromVersion below, which names it in the error. Covered.
	//
	// (2) An unparseable GENERATOR version (version.go:74-77). Here the image
	// parses fine, the guard silently never runs, and a config is generated
	// with nothing downstream to notice — the one case where discarding
	// `checked` really does lose information. It is unreachable while
	// GeneratorVersion() is machinery's own compile-time version constant,
	// which is why it is documented rather than branched on: the day that
	// becomes a build flag or a runtime lookup, this is the line that has to
	// grow a branch.
	if _, err := CheckVersion(version); err != nil {
		return nil, err
	}

	contract, err := config.ParseContractFromVersion(version)
	if err != nil {
		return nil, fmt.Errorf("parsing Talos version %q: %w", version, err)
	}

	k8sVersion, err := kubernetesVersion(version)
	if err != nil {
		return nil, err
	}

	genOpts := []generate.Option{
		// Without a contract every version-gated default is generated for the
		// machinery's own version instead of the image's.
		generate.WithVersionContract(contract),
		// Pinned to the IMAGE. Left unset, Talos substitutes the generator's
		// version and a fresh install silently becomes a cross-version upgrade.
		generate.WithInstallImage(cmp.Or(in.InstallerImage, "ghcr.io/siderolabs/installer:"+version)),
		// A topology correction, not a security weakening: with the
		// control-plane taint in place a single-node cluster schedules nothing.
		generate.WithAllowSchedulingOnControlPlanes(true),
		// apid is dialled at THIS address, which must therefore be in its
		// certificate. Derived from the endpoint by the caller so the two
		// cannot disagree.
		generate.WithAdditionalSubjectAltNames([]string{in.APIAddress}),
		generate.WithEndpointList([]string{in.APIAddress}),
	}

	// OPTIONAL, and empty is a real answer rather than a missing one. Under
	// QEMU the console is the only way to watch a boot, and the installed
	// system inherits nothing from the ISO — so it must be named. On hardware
	// the firmware has already configured a console and there is usually a
	// display, so naming one derived from THIS laptop's architecture is not a
	// default, it is a guess that boots the node with a dead console.
	if in.ConsoleArg != "" {
		genOpts = append(genOpts, generate.WithInstallExtraKernelArgs([]string{in.ConsoleArg}))
	}

	// OPTIONAL, like the console argument above and for the same shape of
	// reason: a machine on a segment that serves DHCP needs nothing here, and
	// emitting a network section for it would replace working defaults with a
	// guess about its NIC.
	if in.Network != nil {
		genOpts = append(genOpts, networkOption(in.Network))
	}

	// THE EXISTING PKI, when there is one. Everything above describes a machine
	// that could be built from scratch; this is what makes the same description
	// apply to a machine that already exists and must keep the identity it was
	// installed with.
	if len(in.SecretsBundle) > 0 {
		bundle, err := parseSecretsBundle(in.SecretsBundle)
		if err != nil {
			return nil, err
		}

		genOpts = append(genOpts, generate.WithSecretsBundle(bundle))
	}

	input, err := generate.NewInput(in.ClusterName, in.Endpoint, k8sVersion, genOpts...)
	if err != nil {
		return nil, fmt.Errorf("preparing config generation: %w", err)
	}

	cfg, err := input.Config(machine.TypeControlPlane)
	if err != nil {
		return nil, fmt.Errorf("generating control plane config: %w", err)
	}

	// The install disk is selected by a STABLE IDENTITY — serial or WWID — and
	// there is no generate.Option that reaches the selector: WithInstallDisk
	// takes a device path, which is exactly the identity we are avoiding.
	// PatchV1Alpha1 is machinery's own supported way in, and it preserves the
	// other documents.
	// UnattendedInstallConfig is a v1alpha1-incompatible way of describing the same thing:
	// Talos rejects a config that carries both it and machine.install. A patch supplying one
	// therefore owns the install, and the generated machine.install is dropped.
	unattended := false

	for _, patch := range in.ConfigPatches {
		if strings.Contains(patch, "UnattendedInstallConfig") {
			unattended = true

			break
		}
	}

	cfg, err = cfg.PatchV1Alpha1(func(c *v1alpha1.Config) error {
		// BOTH ARE OPTIONAL POINTERS. machinery 1.13 always allocates them, but
		// 1.14 stopped emitting machine.install for a config that names no
		// install disk, and dereferencing without this is a nil panic INSIDE a
		// machinery callback -- a segfault with this frame on top and nothing
		// about the config that caused it.
		if c.MachineConfig == nil {
			c.MachineConfig = &v1alpha1.MachineConfig{}
		}

		if c.MachineConfig.MachineInstall == nil {
			c.MachineConfig.MachineInstall = &v1alpha1.InstallConfig{}
		}

		// A selector and a disk are NOT alternatives Talos weighs: it builds its
		// match expression from the selector whenever one is present and never
		// looks at `disk`. So naming the target by path means leaving the
		// selector NIL, not setting both and hoping the more specific one wins.
		if in.SystemDisk.DevPath != "" {
			c.MachineConfig.MachineInstall.InstallDisk = in.SystemDisk.DevPath
			c.MachineConfig.MachineInstall.InstallDiskSelector = nil
		} else {
			c.MachineConfig.MachineInstall.InstallDiskSelector = installDiskSelector(in.SystemDisk)
		}

		// The image is ALSO set here, not only through WithInstallImage above.
		// On machinery 1.14 that option is accepted and then silently
		// discarded: it writes into the machine.install the generator no longer
		// allocates, so the config comes out with no `image:` at all. A caller
		// pinning a patched installer then boots STOCK Talos, and the only
		// symptom is a version string nobody thinks to ask for. Setting it on
		// the struct we have just allocated is the one placement that cannot be
		// dropped, and it is a no-op when the option did work.
		c.MachineConfig.MachineInstall.InstallImage = cmp.Or(
			in.InstallerImage, "ghcr.io/siderolabs/installer:"+version)

		// GATED ON A CONSOLE ARG ACTUALLY BEING PASSED. A 1.12+ contract turns
		// grubUseUKICmdline ON, which makes GRUB take its cmdline from the
		// installer's UKI and IGNORE extraKernelArgs — machinery rejects the two
		// together, so a config carrying a console arg does not even validate in
		// metal mode. Talos 1.8 dropped console=ttyS0 from the metal image's own
		// defaults (imager/quirks), so the arg has to come from here and the UKI
		// cmdline has to yield.
		//
		// With NO console arg there is no conflict to resolve, and switching a
		// node's boot path off the UKI cmdline anyway is a change made for
		// nothing. Only touched when machinery set it: the field is unknown to
		// older Talos, and the contract exists to avoid emitting fields a node
		// cannot parse.
		if unattended {
			// dropped LAST, so registries, sysctls and the rest still apply
			defer func() { c.MachineConfig.MachineInstall = nil }()
		}

		if in.ConsoleArg != "" && c.MachineConfig.MachineInstall.InstallGrubUseUKICmdline != nil {
			c.MachineConfig.MachineInstall.InstallGrubUseUKICmdline = new(false)
		}

		// KEXEC IS DISABLED THROUGH A SYSCTL, and the sysctl is what makes this
		// work at all. Talos applies machine-config sysctls IN MAINTENANCE MODE,
		// so this lands on the ISO's running kernel before the install and
		// therefore before the reboot it needs to change. machined then reports
		// kexec support disabled via sysctl and reboots through firmware.
		//
		// Nothing else reaches that kernel: extraKernelArgs configures the
		// INSTALLED system, which in a failed kexec never boots, and the ISO's
		// own cmdline comes from its GRUB config. This is also exactly what
		// upstream's `talosctl cluster create` does.
		//
		// The value is the string "1" because sysctls is map[string]string.
		if in.DisableKexec {
			if c.MachineConfig.MachineSysctls == nil {
				c.MachineConfig.MachineSysctls = map[string]string{}
			}

			c.MachineConfig.MachineSysctls["kernel.kexec_load_disabled"] = "1"
		}

		// NOT A generate.Option — there is none for registries, so this goes
		// in beside the disk selector through machinery's own supported patch.
		// Guarded on len so an empty input leaves the field absent rather than
		// emitting `registries: {}`, which is noise in every diff of a
		// generated config.
		if len(in.Registries) > 0 {
			c.MachineConfig.MachineRegistries = registriesConfig(in.Registries)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("patching the install section: %w", err)
	}

	// The two ways to get a user volume, and they are MUTUALLY EXCLUSIVE by the
	// caller's construction — a separate data disk, or a slice of the system
	// disk. Both land here as documents of their own rather than v1alpha1
	// patches, so they are appended together or not at all.
	//
	// Documents() builds its result with make() on every call (container.go:693),
	// so appending to it cannot alias the container's own storage and there is
	// nothing to clone.
	if docs, err := volumeDocuments(in); err != nil {
		return nil, err
	} else if len(docs) > 0 {
		cfg, err = container.New(append(cfg.Documents(), docs...)...)
		if err != nil {
			return nil, fmt.Errorf("adding the volume documents: %w", err)
		}
	}

	// LAST, over everything above — machinery's own patch mechanism, the same
	// strategic-merge / JSON6902 shape talosctl --config-patch takes. It is the
	// escape hatch for fields tinq has no dedicated knob for (the motivating one
	// is machine.network.nameservers on the DHCP dev VM, pointed at the seed's
	// DNS so pods resolve *.lab). Applied here so a patch can override the disk
	// selector, registries and volumes this function just set, and so a patch
	// that does not parse or apply fails NOW rather than on a booted node.
	if len(in.ConfigPatches) > 0 {
		patches, err := configpatcher.LoadPatches(in.ConfigPatches)
		if err != nil {
			return nil, fmt.Errorf("loading config patches: %w", err)
		}

		out, err := configpatcher.Apply(configpatcher.WithConfig(cfg), patches)
		if err != nil {
			return nil, fmt.Errorf("applying config patches: %w", err)
		}

		cfg, err = out.Config()
		if err != nil {
			return nil, fmt.Errorf("re-reading the patched config: %w", err)
		}
	}

	controlPlane, err := cfg.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding control plane config: %w", err)
	}

	clientConfig, err := input.Talosconfig()
	if err != nil {
		return nil, fmt.Errorf("generating talosconfig: %w", err)
	}

	talosconfig, err := clientConfig.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding talosconfig: %w", err)
	}

	// Marshalled with machinery's own yaml package so secrets.LoadBundle reads
	// back exactly what we wrote, byte for byte as talosctl writes it.
	secretsBundle, err := yaml.Marshal(input.Options.SecretsBundle)
	if err != nil {
		return nil, fmt.Errorf("encoding secrets bundle: %w", err)
	}

	return &Generated{
		ControlPlane: controlPlane,
		Talosconfig:  talosconfig,
		Secrets:      secretsBundle,
	}, nil
}

// kubernetesVersion is the Kubernetes version to pin into a config generated
// for the given Talos image.
//
// It is NOT constants.DefaultKubernetesVersion. That constant is a property of
// the machinery this binary was built against, and CheckVersion deliberately
// admits any image at or BELOW the generator, so writing it into the config is
// the installer pin's bug one field over: a v1.12 image would be handed
// kubelet, apiserver, scheduler and controller-manager v1.36, which is outside
// Talos 1.12's supported window and fails on the node rather than here.
//
// machinery has no Talos -> Kubernetes MAPPING to ask for. What it has is a
// PREDICATE — compatibility.KubernetesVersion.SupportedWith(*TalosVersion),
// compatibility/kubernetes_version.go — and per-release bounds in
// compatibility/talos1XX; the switch that picks the right bounds for a version
// is unexported, so the bounds cannot be read directly without duplicating
// that table here. The predicate is therefore used as an ORACLE: start at the
// generator's default and step the MINOR down until machinery says yes. No
// version number from that table is copied into this repository, and the
// answer is visible in the generated config as the kubelet image tag.
func kubernetesVersion(talosVersion string) (string, error) {
	target, err := compatibility.ParseTalosVersion(&machineapi.VersionInfo{Tag: talosVersion})
	if err != nil {
		return "", fmt.Errorf("parsing Talos version %q: %w", talosVersion, err)
	}

	major, rest, _ := strings.Cut(constants.DefaultKubernetesVersion, ".")

	minorText, _, _ := strings.Cut(rest, ".")

	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return "", fmt.Errorf("parsing the generator's Kubernetes version %q: %w",
			constants.DefaultKubernetesVersion, err)
	}

	// The generator's default is tried whole, patch included, so an image on
	// the generator's own Talos version gets exactly what talosctl would give
	// it. Only a version we have to step DOWN to loses its patch, and .0 is the
	// one patch every Kubernetes minor release ships.
	candidate := constants.DefaultKubernetesVersion

	var unsupported error

	for ; minor > 0; minor-- {
		k8s, err := compatibility.ParseKubernetesVersion(candidate)
		if err != nil {
			return "", fmt.Errorf("parsing Kubernetes version %q: %w", candidate, err)
		}

		if unsupported = k8s.SupportedWith(target); unsupported == nil {
			return candidate, nil
		}

		candidate = fmt.Sprintf("%s.%d.0", major, minor-1)
	}

	return "", fmt.Errorf(`no Kubernetes version works with a Talos %s image

The kubelet and every control-plane component are pinned BY VERSION in the
generated config, and this build's default (%s) is the config generator's, not
the image's. Walking down from it found nothing machinery accepts: %s

  boot an image this build has compatibility data for, or rebuild tinq against
  a machinery that covers %s`,
		talosVersion, constants.DefaultKubernetesVersion, unsupported, talosVersion)
}

// registriesConfig folds the flat mirror list into the two maps Talos wants.
//
// SEPARATE FROM GenerateConfig so it can be tested without generating a
// cluster's secrets: this is the part with branching in it, and the rest of
// GenerateConfig needs a real Talos version and produces a different answer
// every run.
func registriesConfig(mirrors []RegistryMirror) v1alpha1.RegistriesConfig {
	var out v1alpha1.RegistriesConfig

	for _, m := range mirrors {
		if out.RegistryMirrors == nil {
			out.RegistryMirrors = map[string]*v1alpha1.RegistryMirrorConfig{}
		}

		entry := out.RegistryMirrors[m.Host]
		if entry == nil {
			entry = &v1alpha1.RegistryMirrorConfig{}
			out.RegistryMirrors[m.Host] = entry
		}

		entry.MirrorEndpoints = append(entry.MirrorEndpoints, m.Endpoint)

		if m.OverridePath {
			entry.MirrorOverridePath = new(true)
		}

		// TLS config is a SECOND map. Either a CA to trust or a request to skip
		// verification lands here; a plain http:// mirror needs neither.
		needsTLS := m.InsecureSkipVerify || m.CA != ""
		if !needsTLS {
			continue
		}

		// Talos refuses "*" as a TLS config key; emitting it fails validation
		// on apply, i.e. after a VM has already booted.
		if m.Host == "*" {
			continue
		}

		if out.RegistryConfig == nil {
			out.RegistryConfig = map[string]*v1alpha1.RegistryConfig{}
		}

		tls := &v1alpha1.RegistryTLSConfig{}
		if m.InsecureSkipVerify {
			tls.TLSInsecureSkipVerify = new(true)
		}
		if m.CA != "" {
			// Raw PEM bytes; machinery base64-encodes TLSCA when it renders.
			tls.TLSCA = []byte(m.CA)
		}
		out.RegistryConfig[m.Host] = &v1alpha1.RegistryConfig{RegistryTLS: tls}
	}

	return out
}

// parseSecretsBundle reads a secrets.yaml back into the bundle generation
// wants.
//
// The CLOCK is restored explicitly because yaml skips it (`yaml:"-"` on
// secrets.Bundle.Clock) and generation dereferences it when it issues
// certificates — so a bundle round-tripped through disk without this line
// panics rather than failing.
//
// The bytes are SECRET: five certificate authorities and the machine token.
// Nothing here quotes them, and the parse failure goes through errSecretParse
// for the reason every other secret parse does — the parser's message can
// contain the document.
func parseSecretsBundle(b []byte) (*secrets.Bundle, error) {
	var bundle secrets.Bundle

	if err := yaml.Unmarshal(b, &bundle); err != nil {
		return nil, errSecretParse("secrets bundle")
	}

	// A file that is valid YAML but not a bundle — an empty document, or the
	// wrong file entirely — unmarshals into a struct of nils and would be
	// noticed as a nil dereference deep inside machinery.
	if bundle.Certs == nil || bundle.Secrets == nil || bundle.Cluster == nil {
		return nil, errors.New("the secrets bundle is missing its certificates, cluster or " +
			"machine secrets, so a config generated from it could not be trusted by the node " +
			"it is for")
	}

	bundle.Clock = secrets.NewClock()

	return &bundle, nil
}

// installDiskSelector turns a DiskRef into machinery's install selector.
//
// The two fields are ALTERNATIVES, not a pair: machinery ANDs every non-empty
// field of an InstallDiskSelector, so setting both would demand one disk
// reporting both values and match nothing when the caller meant "either". That
// is why DiskRef.Validate refuses both, and why this switch never falls through
// to setting two.
func installDiskSelector(ref DiskRef) *v1alpha1.InstallDiskSelector {
	switch {
	case ref.WWID != "":
		return &v1alpha1.InstallDiskSelector{WWID: ref.WWID}
	default:
		return &v1alpha1.InstallDiskSelector{Serial: ref.Serial}
	}
}

// volumeDocuments builds the volume documents this machine needs, in the order
// Talos should read them: the EPHEMERAL cap before the user volume that depends
// on the space it frees.
//
// NIL IS THE COMMON ANSWER. A machine with no data disk and no EPHEMERAL cap
// gets no documents at all and behaves exactly as every machine did before
// either field existed.
func volumeDocuments(in ConfigInput) ([]coreconfig.Document, error) {
	switch {
	// A DEDICATED DATA DISK. The user volume is selected by that disk's serial
	// for the same reason the install disk is selected by identity.
	// `!system_disk` is not enough: the boot ISO is a virtio-blk device too.
	case in.DataDiskSerial != "":
		volume, err := userVolume(fmt.Sprintf("disk.serial == %q", in.DataDiskSerial))
		if err != nil {
			return nil, err
		}

		return []coreconfig.Document{volume}, nil

	// ONE DISK, CUT IN TWO. EPHEMERAL is capped so there is free space at all,
	// and the user volume takes what is left of the same disk.
	//
	// BOTH SELECT `system_disk`, which is the only expression that stays true
	// here: the install target may have been named by WWID, and re-deriving
	// that identity in two more places is how the three drift apart. Talos
	// already knows which disk it installed to.
	case in.EphemeralMaxSize != "":
		ephemeral, err := ephemeralCap(in.EphemeralMaxSize)
		if err != nil {
			return nil, err
		}

		volume, err := userVolume("system_disk")
		if err != nil {
			return nil, err
		}

		return []coreconfig.Document{ephemeral, volume}, nil

	default:
		return nil, nil
	}
}

// ephemeralCap bounds Talos's EPHEMERAL volume, which is what leaves free space
// on the system disk for anything else.
//
// NO `grow`, on purpose. EPHEMERAL grows to fill the disk when nothing stops
// it, and the whole point here is to stop it; setting maxSize AND grow would be
// asking for both.
func ephemeralCap(maxSize string) (*block.VolumeConfigV1Alpha1, error) {
	// UnmarshalText rather than MustSize: machinery's constructor PANICS on a
	// bad value, and this one comes from a hand-written manifest. A typo in a
	// YAML field is a refusal, never a stack trace.
	var size block.Size
	if err := size.UnmarshalText([]byte(maxSize)); err != nil {
		return nil, fmt.Errorf("ephemeralMaxSize %q is not a size Talos accepts (try 120GB, or 60%%): %w", maxSize, err)
	}

	// "" unmarshals CLEANLY into a zero Size, so a blank string would sail
	// through above and emit an EPHEMERAL document that caps nothing — leaving
	// the user volume with no free space to grow into and no error to explain
	// it. The caller gates on non-empty; this is the assertion that it did.
	if size.IsZero() {
		return nil, fmt.Errorf("ephemeralMaxSize %q parses to no size at all, so EPHEMERAL would still "+
			"take the whole disk and the user volume would have nowhere to go", maxSize)
	}

	// A UNIT-OMISSION GUARD, and it is the same failure this repo already
	// documents for `dataDisk: 40`: a bare number is VALID here and means
	// BYTES, so `ephemeralMaxSize: 120` asks for a 120-byte /var. Nobody means
	// that, and nothing downstream would say so — the install simply produces a
	// node that cannot hold a container image.
	//
	// The floor is deliberately far below any workable value rather than a
	// guess at one: this refuses typos, not informed choices. A percentage has
	// no unit to omit and is exempt.
	if !size.IsRelative() && size.Value() < ephemeralFloor {
		return nil, fmt.Errorf("ephemeralMaxSize %q is %d bytes, which cannot hold /var — etcd, "+
			"container images and kubelet state all live there\n\n"+
			"  a bare number means BYTES. Did you mean %sGB? Sizes need a unit: 120GB, 100GiB, or 60%%",
			maxSize, size.Value(), maxSize)
	}

	match, err := cel.ParseBooleanExpression("system_disk", celenv.DiskLocator())
	if err != nil {
		return nil, fmt.Errorf("building the EPHEMERAL disk selector: %w", err)
	}

	volume := block.NewVolumeConfigV1Alpha1()
	volume.MetaName = constants.EphemeralPartitionLabel
	volume.ProvisioningSpec = block.ProvisioningSpec{
		DiskSelectorSpec:    block.DiskSelector{Match: match},
		ProvisioningMaxSize: size,
	}

	return volume, nil
}

// userVolume describes the PVC volume, on whichever disk `expr` selects.
//
// It is a partition rather than a whole-disk volume, and it grows: on a
// dedicated data disk the disk is its own anyway and a partitioned volume is
// the path Talos's own storage guide documents; on a shared system disk `grow`
// is what makes it claim the space the EPHEMERAL cap left behind.
func userVolume(expr string) (*block.UserVolumeConfigV1Alpha1, error) {
	match, err := cel.ParseBooleanExpression(expr, celenv.DiskLocator())
	if err != nil {
		return nil, fmt.Errorf("building a disk selector from %q: %w", expr, err)
	}

	volume := block.NewUserVolumeConfigV1Alpha1()
	volume.MetaName = userVolumeName
	volume.VolumeType = new(blockres.VolumeTypePartition)
	volume.ProvisioningSpec = block.ProvisioningSpec{
		DiskSelectorSpec:    block.DiskSelector{Match: match},
		ProvisioningMinSize: block.MustByteSize("1GiB"),
		ProvisioningGrow:    new(true),
	}
	volume.FilesystemSpec = block.FilesystemSpec{FilesystemType: blockres.FilesystemTypeXFS}

	return volume, nil
}
