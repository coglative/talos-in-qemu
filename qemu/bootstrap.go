package qemu

import (
	"context"
	"log"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/coglative/talos-in-qemu/driverkit"
)

// bringUpOnce drives a running machine to a single-node cluster, at most one attempt at a time.
//
// This is the CLI's `up` reached from the controller, and it stays inside the boundary the CRD
// states: the split is BOOTSTRAP vs STEADY STATE, and cluster.Up creates a cluster once and never
// upgrades, scales or reconciles one. Anything ongoing is still provider-talos's -- which cannot
// create this cluster, because it runs inside a cluster.
//
// Without it the controller stops at a booted VM in maintenance mode: apid answers, the disk is
// never written, and powerState reads Running for a machine that is not a cluster.
//
// ASYNCHRONOUS, because reconciliation is serial. cluster.Up takes minutes, and running it inline
// would hold every other machine on this node for the whole bring-up. The guard admits one attempt
// per machine; a second tick while one is in flight is a no-op rather than a second installer
// against the same disk.
//
// Re-running is safe by design: `up` skips config generation and apply-config for a machine that is
// already configured, and treats a bootstrap the node refuses because etcd exists as success. So a
// handler restart, which loses this process-local memory, costs a fast no-op rather than a rebuild.
type bootstrapper struct {
	mu       sync.Mutex
	inFlight map[string]bool
}

func newBootstrapper() *bootstrapper {
	return &bootstrapper{inFlight: map[string]bool{}}
}

func (b *bootstrapper) begin(uid string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inFlight[uid] {
		return false
	}
	b.inFlight[uid] = true
	return true
}

func (b *bootstrapper) done(uid string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.inFlight, uid)
}

var bootstraps = newBootstrapper()

// wantsBootstrap reports whether the machine asks the controller to drive it to a cluster.
//
// Opt-in per machine rather than implied by role: a talos-cp that someone else bootstraps is a
// legitimate shape, and inferring the intent from the role would take that away silently.
func wantsBootstrap(m *unstructured.Unstructured) bool {
	v, _, _ := unstructured.NestedBool(m.Object, "spec", "bootstrap")
	return v
}

func maybeBootstrap(ctx context.Context, d *hvf, m *unstructured.Unstructured,
	state driverkit.State, status map[string]interface{}) {
	if !wantsBootstrap(m) || state != driverkit.Running {
		return
	}
	uid := string(m.GetUID())
	if !bootstraps.begin(uid) {
		return
	}
	name := m.GetName()
	go func() {
		defer bootstraps.done(uid)
		log.Printf("%s: bringing up the cluster", name)
		if err := bringUp(context.WithoutCancel(ctx), d, m, state, status); err != nil {
			log.Printf("%s: bring-up: %v", name, err)
			return
		}
		log.Printf("%s: cluster up", name)
	}()
}
