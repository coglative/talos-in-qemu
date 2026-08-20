// Command tinq reconciles TalosMachine resources into QEMU virtual machines.
//
// The implementation lives in package qemu so a controller can bind the driver directly. This is
// the shim that move promised and did not add: `go build ./...` has no main package to fail on, so
// a tree with no entrypoint builds and tests clean while the Dockerfile cannot resolve its target.
// Guarded by qemu.TestImageEntrypointBuilds.
package main

import "github.com/coglative/talos-in-qemu/qemu"

func main() { qemu.Main() }
