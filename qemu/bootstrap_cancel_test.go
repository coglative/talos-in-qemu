package qemu

import (
	"testing"
	"time"
)

// A bring-up must be CANCELLABLE, or teardown loses a race it cannot see.
//
// This used context.WithoutCancel, so a run in flight could not be stopped by anything. cluster.Up
// calls create(), so a bring-up still running when the machine is destroyed rebuilds the disk and
// boots qemu against an object that no longer exists.
//
// Measured 2 of 2 on a teardown loop, and it presents as Destroy having silently failed:
//
//	teardown reported complete, releasing the finalizer     <- Destroy ran and cleaned up
//	qemu_running=2  state_dir_present=yes                   <- the goroutine put it back
//
// The state dir reappears under the SAME UID, which is what made the first sighting look like a
// teardown that never ran rather than one that was undone.
func TestBringUpIsCancellable(t *testing.T) {
	b := newBootstrapper()
	ctx, ok := b.begin("u1")
	if !ok {
		t.Fatal("first attempt was not admitted")
	}
	select {
	case <-ctx.Done():
		t.Fatal("the context is already cancelled before anything asked for it")
	default:
	}

	b.cancel("u1")

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not stop the bring-up; a run in flight will recreate what Destroy removed")
	}
}

// Cancelling one machine's bring-up must not stop another's.
func TestCancelIsPerMachine(t *testing.T) {
	b := newBootstrapper()
	a, _ := b.begin("u1")
	c, _ := b.begin("u2")

	b.cancel("u1")

	select {
	case <-a.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("u1 was not cancelled")
	}
	select {
	case <-c.Done():
		t.Fatal("cancelling u1 stopped u2's bring-up")
	default:
	}
}

// Cancelling a machine with nothing in flight is a no-op, not a panic: Destroy calls this
// unconditionally, including for machines that never asked to be bootstrapped.
func TestCancelUnknownMachineIsHarmless(t *testing.T) {
	newBootstrapper().cancel("never-started")
}
