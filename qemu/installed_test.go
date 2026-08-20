package qemu

import (
	"os"
	"path/filepath"
	"testing"
)

func diskOfSize(t *testing.T, n int64) string {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "system.qcow2"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(n); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A freshly created disk still needs the installer.
//
// `qemu-img create` writes headers only -- 196,928 bytes measured for a 20Gi system disk. Dropping
// the ISO here would leave a machine with nothing to boot, which presents as a guest that never
// answers rather than as a missing device.
func TestFreshDiskKeepsTheInstallMedia(t *testing.T) {
	if !attachInstallMedia(diskOfSize(t, 196928)) {
		t.Fatal("a created-but-empty disk was denied the installer it still needs")
	}
}

// An installed disk must NOT be offered the ISO.
//
// bootindex puts the disk first, but OVMF persists BootOrder in efivars, and once an ISO entry
// exists it can win a later boot. Measured: a venue installed, ran the installed system for 44s,
// then rebooted into the ISO menu and came back in maintenance mode with a different CA -- the
// bring-up then failed at bootstrap with an x509 error that says nothing about boot order.
func TestInstalledDiskDropsTheInstallMedia(t *testing.T) {
	if attachInstallMedia(diskOfSize(t, 115867648)) {
		t.Fatal("an installed system was still offered the ISO, which can win the next boot")
	}
}

// A missing disk is not an installed one. Absent must not read as installed, or a machine whose
// state was destroyed comes back with no way to install itself.
func TestMissingDiskIsNotInstalled(t *testing.T) {
	if diskHasBeenInstalledTo(t.TempDir()) {
		t.Fatal("a state dir with no disk reported an installed system")
	}
	if !attachInstallMedia(t.TempDir()) {
		t.Fatal("a machine with no disk was denied the installer")
	}
}
