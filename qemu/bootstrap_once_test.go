package qemu

import "testing"

// A machine is brought up ONCE, not once per tick.
//
// The in-flight guard only stops two runs OVERLAPPING. After each success the next tick started
// another: measured at 18 bring-ups in 12 minutes, one per interval, each a fast no-op because `up`
// skips completed steps.
//
// That is not harmless. It means a bring-up is almost ALWAYS in flight, and a teardown landing on
// one leaks the VM — which is what made teardown look randomly broken across an entire session.
func TestBringUpHappensOncePerMachine(t *testing.T) {
	b := newBootstrapper()

	if _, ok := b.begin("u1"); !ok {
		t.Fatal("first attempt was refused")
	}
	b.done("u1", true)

	if _, ok := b.begin("u1"); ok {
		t.Fatal("a machine already brought up started another bring-up on the next tick")
	}
}

// A FAILED attempt must stay retryable, or one bad run strands the venue until the handler restarts.
func TestFailedBringUpIsRetried(t *testing.T) {
	b := newBootstrapper()

	if _, ok := b.begin("u1"); !ok {
		t.Fatal("first attempt was refused")
	}
	b.done("u1", false)

	if _, ok := b.begin("u1"); !ok {
		t.Fatal("a failed bring-up was not retried; the venue is stranded until a restart")
	}
}

// Completion is per machine: one venue finishing must not stop another from starting.
func TestCompletionDoesNotBlockOtherMachines(t *testing.T) {
	b := newBootstrapper()
	b.begin("u1")
	b.done("u1", true)

	if _, ok := b.begin("u2"); !ok {
		t.Fatal("a different machine was blocked by another's completed bring-up")
	}
}
