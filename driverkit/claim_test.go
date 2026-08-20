package driverkit

import (
	"context"
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A machine already claimed by another node must not be reconciled here.
//
// Run lists with no selector, so every replica of a driver sees every machine. Serial
// reconciliation inside one process is what stopped two qemu processes reaching one state dir, and
// that guarantee does not survive a second process: three handlers on three nodes each observed the
// same machine Absent on their OWN disk and each created it, so one CR produced three VMs and the
// last status write named whichever won the race.
func TestReconcileSkipsMachineClaimedByAnotherNode(t *testing.T) {
	m := managed("Running")
	if err := unstructured.SetNestedField(m.Object, "other-node", "status", "node"); err != nil {
		t.Fatal(err)
	}
	d := &fakeDriver{state: Absent}
	ri := &fakeResource{}
	cfg := Config{Finalizer: testFinalizer, NodeName: "this-node"}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, cfg, d, m); err != nil {
		t.Fatalf("a machine belonging to another node is not an error here: %v", err)
	}
	if d.created != 0 {
		t.Fatal("created a VM for a machine another node holds — this is the duplicate-VM bug")
	}
	if len(ri.patches) != 0 {
		t.Fatalf("wrote status for a machine another node holds: %v", ri.patches)
	}
}

// An unclaimed machine is claimed before anything is created, and the claim names this node.
func TestReconcileClaimsUnclaimedMachine(t *testing.T) {
	d := &fakeDriver{state: Absent}
	ri := &fakeResource{}
	cfg := Config{Finalizer: testFinalizer, NodeName: "this-node"}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, cfg, d, managed("Running")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if d.created == 0 {
		t.Fatal("did not create after claiming")
	}
	if got := claimedNode(t, ri); got != "this-node" {
		t.Fatalf("claim names %q, want this-node", got)
	}
}

// The claim must be a NODE-SCOPED fact, so a driver with no node configured keeps working exactly
// as before. This is what lets a single-process `tinq controller` stay unchanged.
func TestReconcileWithoutNodeNameDoesNotClaim(t *testing.T) {
	m := managed("Running")
	if err := unstructured.SetNestedField(m.Object, "other-node", "status", "node"); err != nil {
		t.Fatal(err)
	}
	d := &fakeDriver{state: Absent}
	ri := &fakeResource{}

	if err := reconcile(context.Background(), &fakeDynamic{ri: ri}, Config{Finalizer: testFinalizer}, d, m); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if d.created == 0 {
		t.Fatal("an unconfigured driver must reconcile every machine, as it did before claiming existed")
	}
}

func claimedNode(t *testing.T, ri *fakeResource) string {
	t.Helper()
	for _, p := range ri.patches {
		var got struct {
			Status struct {
				Node string `json:"node"`
			} `json:"status"`
		}
		if err := json.Unmarshal(p.body, &got); err == nil && got.Status.Node != "" {
			return got.Status.Node
		}
	}
	return ""
}
