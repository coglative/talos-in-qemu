// Package platform resolves the host-specific facts a QEMU invocation needs:
// which emulator binary, which machine type, which accelerator, and where the
// UEFI firmware lives.
//
// Everything here is decided at RUNTIME rather than by build tags. Build tags
// would leave the macOS path uncompiled on Linux — no type checking, no tests,
// no compile error until someone builds on a Mac. The variance is four values
// and a firmware lookup; that does not justify hiding half the code from the
// compiler.
package platform

import (
	"fmt"
	"runtime"
	"slices"
)

// Platform is the set of host facts main.go needs. Fields are resolved once by
// Detect and then only read.
type Platform struct {
	// OS is the host's GOOS. It is carried here rather than left to callers'
	// own runtime.GOOS so that EVERY host fact a caller reports comes from one
	// injectable struct. A caller reaching for runtime.GOOS directly cannot be
	// tested against a host other than the one the test binary runs on, which
	// is how a transcript line ended up asserting "linux/amd64" and failing on
	// a Mac while the code above it was correct.
	OS           string // linux | darwin
	QEMUBinary   string // qemu-system-x86_64 | qemu-system-aarch64
	Machine      string // q35 | virt
	Accel        string // kvm | hvf
	CPU          string // host — only legal with a hardware accelerator
	FirmwareCode string // read-only pflash
	FirmwareVars string // nvram TEMPLATE, copied verbatim — never padded
	ConsoleArg   string // console=ttyS0 | console=ttyAMA0 (guest hint)
	ImageArch    string // amd64 | arm64 (guest hint, used by the image guard)
	// TPMDevice is the qemu device model for an emulated TPM 2.0, and it is
	// ARCH-SPECIFIC rather than a constant: x86_64 offers tpm-crb, the
	// interface UEFI guests expect, while aarch64 offers neither tpm-crb nor
	// tpm-tis -- `qemu-system-aarch64 -device help` lists only
	// tpm-tis-device. Naming the wrong one is not a warning; qemu refuses to
	// start, and the machine never appears.
	TPMDevice string
}

type archInfo struct {
	qemuBinary string
	machine    string
	console    string
	imageArch  string
	fwArch     string // the "architecture" value used in firmware descriptors
	tpmDevice  string // qemu device model for an emulated TPM 2.0
}

// archFor maps Go's arch vocabulary onto QEMU's. They disagree: Go says amd64
// and arm64, QEMU says x86_64 and aarch64, and the firmware registry uses
// QEMU's spelling.
func archFor(goarch string) (archInfo, error) {
	switch goarch {
	case "amd64":
		return archInfo{"qemu-system-x86_64", "q35", "console=ttyS0", "amd64", "x86_64", "tpm-crb"}, nil
	case "arm64":
		return archInfo{"qemu-system-aarch64", "virt", "console=ttyAMA0", "arm64", "aarch64", "tpm-tis-device"}, nil
	}
	return archInfo{}, fmt.Errorf("unsupported host architecture %q: TinQ supports amd64 and arm64", goarch)
}

// Detect resolves every host fact needed to launch a VM. It fails rather than
// degrading: a wrong guess here surfaces as a silent hang inside QEMU, which is
// far more expensive to diagnose than an error at startup.
func Detect() (*Platform, error) {
	ai, err := archFor(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	accel, err := accelFor(runtime.GOOS)
	if err != nil {
		return nil, err
	}

	// The error already names the binary and the probe that failed, so this
	// only adds the remedy.
	accels, err := compiledAccels(ai.qemuBinary)
	if err != nil {
		return nil, fmt.Errorf("%w\n\ninstall QEMU (the package providing %s)", err, ai.qemuBinary)
	}
	compiled := slices.Contains(accels, accel)

	// There is no HVF analogue to probe, so darwin is judged on the compiled-in
	// answer alone and diag stays kvmOK.
	diag := kvmOK
	var diagErr error
	if runtime.GOOS == "linux" {
		diag, diagErr = diagnoseKVM("/dev/kvm")
	}
	if !compiled || diag != kvmOK {
		return nil, accelUnavailable(runtime.GOOS, runtime.GOARCH, accel, compiled, diag, diagErr)
	}

	code, vars, err := resolveFirmware(registryDirs, fallbackTable, runtime.GOOS, ai.fwArch, ai.machine)
	if err != nil {
		return nil, err
	}

	return &Platform{
		OS:           runtime.GOOS,
		QEMUBinary:   ai.qemuBinary,
		Machine:      ai.machine,
		Accel:        accel,
		CPU:          "host", // only legal with a hardware accelerator, verified above
		FirmwareCode: code,
		FirmwareVars: vars,
		ConsoleArg:   ai.console,
		ImageArch:    ai.imageArch,
		TPMDevice:    ai.tpmDevice,
	}, nil
}
