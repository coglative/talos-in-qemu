package driverkit

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// deletingOn returns a machine being deleted and claimed by node.
func deletingOn(node string) *unstructured.Unstructured {
	m := managed("Running")
	now := metav1.Now()
	m.SetDeletionTimestamp(&now)

	if node != "" {
		if err := unstructured.SetNestedField(m.Object, node, "status", "node"); err != nil {
			panic(err)
		}
	}

	return m
}

// THE DELETE PATH IS NODE-SCOPED TOO, and it was the one place that was not.
//
// Measured 2026-08-20: r3k1n3 held the VM -- qemu pid 50, a state dir, a bring-up in flight -- and
// r3k1n2 logged "teardown reported complete, releasing the finalizer" for it. r3k1n2's Destroy was
// truthful about r3k1n2, where there was nothing, and it cleared the one thing that would have made
// the holder tear its VM down. The CR vanished; the VM ran on. Whichever handler ticks first
// decides, so the same teardown is clean or leaks at random.
func TestReconcileDoesNotDestroyAMachineAnotherNodeHolds(t *testing.T) {
	d := &fakeDriver{state: Running}
	ri := &fakeResource{}
	cfg := Config{Finalizer: testFinalizer, NodeName: "this-node"}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, cfg, d, deletingOn("other-node")); err != nil {
		t.Fatalf("a deletion belonging to another node is not an error here: %v", err)
	}

	if d.destroyed != 0 {
		t.Fatal("destroyed a machine another node holds")
	}

	if len(ri.patches) != 0 {
		t.Fatalf("released the holder's finalizer: %v", ri.patches)
	}
}

// The holder still tears down, or the guard above would trade a leak for a wedge.
func TestReconcileDestroysAMachineThisNodeHolds(t *testing.T) {
	d := &fakeDriver{state: Running}
	ri := &fakeResource{}
	cfg := Config{Finalizer: testFinalizer, NodeName: "this-node"}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, cfg, d, deletingOn("this-node")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if d.destroyed != 1 {
		t.Fatalf("destroy called %d times, want 1", d.destroyed)
	}

	if len(ri.patches) != 1 {
		t.Fatalf("want one finalizer patch, got %v", ri.patches)
	}
}

// AN UNCLAIMED MACHINE MUST STILL BE RELEASABLE, or the fix trades a leak for a wedged finalizer.
func TestReconcileReleasesAnUnclaimedDeletedMachine(t *testing.T) {
	d := &fakeDriver{state: Absent}
	ri := &fakeResource{}
	cfg := Config{Finalizer: testFinalizer, NodeName: "this-node"}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, cfg, d, deletingOn("")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(ri.patches) != 1 {
		t.Fatalf("an unclaimed deleted machine was not released: %v", ri.patches)
	}
}

// A single-process controller has no node name: it holds everything, and nothing here changes.
func TestReconcileWithoutNodeNameStillDestroys(t *testing.T) {
	d := &fakeDriver{state: Running}
	_, err := runReconcile(d, deletingOn("other-node"))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if d.destroyed != 1 {
		t.Fatalf("destroy called %d times, want 1", d.destroyed)
	}
}
