package qemu

import (
	"os"
	"path/filepath"
)

// freshDiskCeiling is the largest a qcow2 gets from being CREATED rather than written to.
//
// `qemu-img create` writes only headers and L1 tables -- measured at 196,928 bytes for a 20Gi
// system disk. An installed Talos is two orders of magnitude past that (115,867,648 bytes measured
// on the first successful install), so this discriminates the two without parsing the image.
const freshDiskCeiling = 16 << 20

// diskHasBeenInstalledTo reports whether the system disk holds a system.
//
// Read from the disk's own size rather than from a flag this process writes, because the two can
// disagree and only one of them is the fact: a marker survives a wipe, and a state dir that was
// destroyed and rebuilt would carry a marker describing a disk that no longer exists. The disk is
// in the same directory it describes.
func diskHasBeenInstalledTo(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "system.qcow2"))
	if err != nil {
		return false
	}
	return fi.Size() > freshDiskCeiling
}

// attachInstallMedia reports whether this boot should be offered the ISO.
//
// ONLY UNTIL THE SYSTEM IS INSTALLED. bootindex puts the disk first, and that is what the firmware
// uses to build its boot list on a machine that has never booted -- but OVMF persists BootOrder in
// efivars, and once an entry for the ISO exists it can win a later boot. Measured: a venue
// installed, booted the installed system for 44s, and then rebooted straight back into the ISO's
// menu. It came up in maintenance mode with a different CA, so the bring-up failed at bootstrap
// with "x509: certificate signed by unknown authority ... talos" -- an error that says nothing
// about boot order, which is what made it expensive to find.
//
// Removing the media is better than fighting the boot list: an installed machine has no use for the
// installer, and a device that is not there cannot be chosen.
func attachInstallMedia(dir string) bool {
	return !diskHasBeenInstalledTo(dir)
}
