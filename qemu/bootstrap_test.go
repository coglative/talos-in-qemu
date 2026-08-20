package qemu

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func bootstrapMachine(want bool) *unstructured.Unstructured {
	m := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "machine.hvf.fleet.io/v1alpha1",
		"kind":       "TalosMachine",
		"metadata":   map[string]interface{}{"name": "m", "uid": "u1"},
		"spec":       map[string]interface{}{"site": "s", "role": "talos-cp"},
	}}
	if want {
		unstructured.SetNestedField(m.Object, true, "spec", "bootstrap")
	}
	return m
}

// Bootstrap is OPT-IN. A machine that does not ask is left in maintenance mode, which is what
// someone bootstrapping it another way depends on.
func TestWantsBootstrapIsOptIn(t *testing.T) {
	if wantsBootstrap(bootstrapMachine(false)) {
		t.Fatal("a machine with no spec.bootstrap must not be driven to a cluster")
	}
	if !wantsBootstrap(bootstrapMachine(true)) {
		t.Fatal("spec.bootstrap: true was not read")
	}
}

// Only one bring-up per machine at a time.
//
// cluster.Up takes minutes and the loop ticks every 10s, so without this guard every tick starts
// another installer against the same disk -- the concurrent-writers failure driverkit's own comment
// says corrupts the state dir, arrived at from a different direction.
func TestBootstrapAdmitsOneAttemptPerMachine(t *testing.T) {
	b := newBootstrapper()
	if _, ok := b.begin("u1"); !ok {
		t.Fatal("the first attempt must be admitted")
	}
	if _, ok := b.begin("u1"); ok {
		t.Fatal("a second attempt ran while the first was in flight")
	}
	if _, ok := b.begin("u2"); !ok {
		t.Fatal("a different machine must not be blocked by another's bring-up")
	}
	b.done("u1", false)
	if _, ok := b.begin("u1"); !ok {
		t.Fatal("after an attempt finishes, a retry must be admitted -- bring-up is idempotent")
	}
}
