package platform

import (
	"encoding/binary"
	"os"
	"strings"
)

const sectorSize = 2048

// InspectImageArch reports the architecture of a Talos boot ISO, or "" when it
// cannot tell. It NEVER returns an error: unknown disables the mismatch guard
// rather than rejecting an image we merely fail to understand. spec.image also
// permits raw disk images, which this cannot parse and must wave through.
//
// Three plausible cheaper methods are wrong, verified against real v1.9.5
// images:
//
//   - ESP boot filenames: Talos ships BOTH BOOTX64.EFI and BOOTAA64.EFI, as
//     real PE binaries with contradictory machine types, in the SAME amd64 ISO.
//   - whole-file PE machine histogram: ambiguous — amd64 has {0x8664:4,
//     0xaa64:2}, arm64 has {0x8664:3, 0xaa64:3}.
//   - the arm64 Image magic at 0x38: ABSENT from the arm64 ISO, because that
//     kernel is an EFI-stub PE rather than a raw Image.
//
// Only the kernel at /BOOT/VMLINUZ* is authoritative. Reads ~8 KB of a real
// 100 MB image, never the whole file — but the directory lengths are read FROM
// the image, so a hostile one can drive the two findChild calls to their cap of
// 1 MiB each: ~2 MiB worst case, bounded, and still not the whole file.
//
// Every length and extent below comes from the file itself, so treat all of it
// as hostile: a malformed image must fall out as "" and never panic.
func InspectImageArch(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	pvd := make([]byte, sectorSize)
	if _, err := f.ReadAt(pvd, 16*sectorSize); err != nil {
		return ""
	}
	// CD001 identifies a volume descriptor; byte 0 is its TYPE, and only type 1
	// is the primary descriptor whose byte 156 holds the root directory record.
	// A boot record (type 0) or a supplementary descriptor (type 2) also says
	// CD001 at sector 16 on some images, and reading a root extent out of one
	// is reading a different structure.
	if string(pvd[1:6]) != "CD001" || pvd[0] != 1 {
		return ""
	}

	rootExtent, rootLen := recordExtent(pvd[156:])
	bootExtent, bootLen, ok := findChild(f, rootExtent, rootLen, func(n string) bool {
		return n == "BOOT"
	})
	if !ok {
		return ""
	}
	kExtent, _, ok := findChild(f, bootExtent, bootLen, func(n string) bool {
		return strings.HasPrefix(n, "VMLINUZ")
	})
	if !ok {
		return ""
	}

	// A short read is not an error here: a kernel at the tail of the file still
	// yields whatever header bytes exist, and peMachine bounds-checks the rest.
	head := make([]byte, 1024)
	n, _ := f.ReadAt(head, int64(kExtent)*sectorSize)
	switch peMachine(head[:n]) {
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	}
	return ""
}

// InspectImageVersion reports the Talos version of a boot ISO from its ISO9660
// volume identifier, or "" when it cannot tell. Like InspectImageArch it never
// errors: unknown disables the version guard rather than blocking an image we
// merely fail to classify.
//
// Talos writes the volume id as TALOS_V<major>_<minor>_<patch>, e.g.
// TALOS_V1_13_7. This is far cheaper than parsing the kernel and is the same
// string file(1) reports. The id is a fixed 32-byte field at PVD offset 40,
// space-padded, so the whole read is one bounded sector and every index below
// is into a slice we allocated at a fixed size.
func InspectImageVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	pvd := make([]byte, sectorSize)
	// A SHORT read is a truncated download, not a usable descriptor: the id at
	// offset 40 can arrive intact in a PVD that was never fully written, and
	// reporting a version off that is reporting one the image may not boot.
	if _, err := f.ReadAt(pvd, 16*sectorSize); err != nil {
		return ""
	}
	// Same reasoning as InspectImageArch: CD001 only says "a volume
	// descriptor", and only type 1 is the PRIMARY one whose offset 40 is the
	// volume identifier.
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return ""
	}

	volID := strings.TrimSpace(string(pvd[40:72]))
	rest, ok := strings.CutPrefix(volID, "TALOS_V")
	if !ok {
		return ""
	}
	parts := strings.Split(rest, "_")
	// A PRE-RELEASE id carries its channel in the same underscore-separated
	// field: TALOS_V1_14_0_BETA_1 is v1.14.0-beta.1. Requiring exactly three
	// components rejected every rc and beta image outright, and the caller
	// cannot tell that refusal from "not a Talos ISO" -- both are "". A release
	// candidate is the image you most want to be running when you are testing a
	// fix against an unreleased Talos.
	if len(parts) != 3 && len(parts) != 5 {
		return ""
	}
	for i, p := range parts {
		// Split yields empty strings for "1__7", and the digit loop below
		// accepts an empty component by iterating zero times.
		if p == "" {
			return ""
		}
		// Component 4 is the channel name (BETA, RC, ALPHA) and is the only
		// non-numeric one; everything else must still be digits, so a stray
		// word cannot smuggle itself into a version string.
		if i == 3 {
			for _, r := range p {
				if r < 'A' || r > 'Z' {
					return ""
				}
			}

			continue
		}

		for _, r := range p {
			if r < '0' || r > '9' {
				return ""
			}
		}
	}

	if len(parts) == 5 {
		return "v" + strings.Join(parts[:3], ".") + "-" + strings.ToLower(parts[3]) + "." + parts[4]
	}

	return "v" + strings.Join(parts, ".")
}

// recordExtent pulls the little-endian extent LBA and byte length out of an
// ISO9660 directory record.
func recordExtent(rec []byte) (uint32, uint32) {
	if len(rec) < 18 {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(rec[2:6]), binary.LittleEndian.Uint32(rec[10:14])
}

// findChild walks one ISO9660 directory extent looking for a matching entry.
// length is attacker-controlled, so it is capped before it becomes an
// allocation; a zero length needs no special case, it simply walks nothing.
func findChild(f *os.File, extent, length uint32, match func(string) bool) (uint32, uint32, bool) {
	if length > 1<<20 {
		return 0, 0, false
	}
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, int64(extent)*sectorSize); err != nil {
		return 0, 0, false
	}
	for off := 0; off < len(buf); {
		// A record shorter than the 33-byte fixed header is either the zero
		// padding that ends a sector or corruption; both mean stop. A directory
		// spanning several sectors therefore stops at the first padding — Talos
		// has no such directory, and stopping early yields "" rather than a
		// wrong answer, which is the direction this is allowed to fail in.
		rl := int(buf[off])
		if rl < 33 || off+rl > len(buf) {
			break
		}
		// Three-index: nameLen is read from the record and indexes into rec, so
		// capping rec's CAPACITY at the record makes that bound structural
		// rather than a property of the 33+nameLen <= rl check below.
		rec := buf[off : off+rl : off+rl]
		nameLen := int(rec[32])
		if 33+nameLen <= rl {
			name := string(rec[33 : 33+nameLen])
			if match(name) {
				e, l := recordExtent(rec)
				return e, l, true
			}
		}
		off += rl
	}
	return 0, 0, false
}

// peMachine returns the COFF machine word of a PE image, or 0 if head is not
// one. head may be short, so every offset is checked against it.
func peMachine(head []byte) uint16 {
	if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
		return 0
	}
	// Unsigned end to end: e_lfanew is a uint32 in the file, so widening it to
	// int is what would let a hostile value go negative. len(head) is at least
	// 0x40 by the check above, so the bound cannot underflow, and lfanew == 0
	// needs no case of its own — the PE signature check below rejects it.
	lfanew := binary.LittleEndian.Uint32(head[0x3c:0x40])
	if lfanew > uint32(len(head)-6) {
		return 0
	}
	if string(head[lfanew:lfanew+4]) != "PE\x00\x00" {
		return 0
	}
	return binary.LittleEndian.Uint16(head[lfanew+4 : lfanew+6])
}
