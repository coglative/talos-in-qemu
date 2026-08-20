package qemu

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// installSelf copies this binary to dest and exits.
//
// WHY A BINARY SHIPS ITSELF. tinq needs qemu at runtime, and qemu is not in a distroless image. The
// alternatives are worse: a Dockerfile that installs qemu beside the binary needs a container builder
// nobody has here, and a runtime that shells out to a package manager on every start makes a pod's
// behaviour depend on a network fetch at the worst moment.
//
// So the same pattern branchspace already uses for its shim and mcp binaries: a tiny image carrying
// only this binary runs as an INIT CONTAINER, copies itself into an emptyDir, and the runtime
// container -- any image that already has qemu -- mounts that volume and executes it. Two images,
// each doing one thing, and neither needs to know how to build the other.
//
// -install RATHER THAN A SHELL COMMAND, because a ko-built image is distroless: there is no `cp`,
// no shell, and nothing else in it. The binary is the only thing that can move the binary.
func installSelf(dest string) error {
	if dest == "" {
		return fmt.Errorf("-install requires a destination path")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating this binary: %w", err)
	}
	src, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("opening %s: %w", self, err)
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(dest), err)
	}
	// WRITE THEN RENAME. A runtime container can start while the init container is still copying if
	// the volume is shared and the pod is restarted oddly; a half-written binary at the final path
	// fails with "exec format error", which names the file and not the race.
	tmp := dest + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return fmt.Errorf("copying to %s: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("installing to %s: %w", dest, err)
	}
	fmt.Fprintf(os.Stderr, "tinq: installed to %s\n", dest)
	return nil
}
