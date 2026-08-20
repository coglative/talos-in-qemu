package qemu

import (
	"fmt"
	"os"
	"sync"

	"github.com/coglative/talos-in-qemu/driverkit"
	"github.com/coglative/talos-in-qemu/platform"
)

// New builds the qemu driver for an embedder — a controller that wants to run machines IN-PROCESS
// rather than shell out to this binary.
//
// WHY THIS EXISTS. The driver was always the right shape: driverkit.Driver, four verbs, already
// tested. The only thing stopping anyone binding it was that the type lived in `package main`,
// which cannot be imported. That is where the code happened to be written, not a decision.
//
// The cost of not having it, measured: a consumer needing a Talos guest wrapped this binary in a
// container, invented an init container to place it, taught the binary to copy itself, and then
// still needed a runtime image carrying qemu. Three artifacts and a new install verb, to avoid a
// `go get`. Before that, the same consumer reimplemented qemu invocation in a shell script and
// re-derived four things this package already knew — bootindex over `-boot d`, disk-by-serial over
// `/dev/vda`, `console=ttyS0` per arch, hostfwd needing an explicit address.
//
// stateRoot is where machines keep their disks and pidfiles; imageRoot is where non-absolute
// spec.image profile names resolve. Both are the embedder's to choose, because both are properties
// of the HOST the VMs run on, and this package deliberately does not guess at one.
func New(stateRoot, imageRoot string) (driverkit.Driver, error) {
	if stateRoot == "" {
		// REFUSED RATHER THAN DEFAULTED. A guessed state root is where a machine's disk quietly goes;
		// getting it wrong orphans the disk rather than failing, and the machine comes back as a
		// fresh one with no indication that the old is still on disk somewhere.
		return nil, fmt.Errorf("stateRoot is required: it is where machine disks and pidfiles live, " +
			"and a guessed one orphans them silently")
	}
	if err := os.MkdirAll(stateRoot, 0o755); err != nil {
		return nil, fmt.Errorf("state root: %w", err)
	}
	return &hvf{
		stateRoot: stateRoot,
		imageRoot: imageRoot,
		// Detect execs `qemu-system-X -accel help` and walks the firmware registries. OnceValues
		// because create() runs on every reconcile tick where Observe reports Absent, and paying for
		// a process exec per tick is how a controller's loop becomes the expensive part.
		detect: sync.OnceValues(platform.Detect),
	}, nil
}
