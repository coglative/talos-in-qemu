package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A config that was WRITTEN but never APPLIED must be applied on the next run.
//
// Step 6 writes the artifacts before step 7 sends them, deliberately, so a failed apply leaves
// something to read. The cost is that the file outlives an apply that never landed -- and on the
// next run the talosconfig makes the machine look configured, so the run skips to waiting for an
// installed system that does not exist. Every retry then spends the whole install budget the same
// way.
//
// A human clears the state dir. A CONTROLLER retries on a timer forever, so a venue that lands here
// never becomes a cluster. Asking the node tells the two apart: still in maintenance means the
// config never arrived.
func TestUpResumesAnApplyThatNeverLanded(t *testing.T) {
	f := newFixture(t)
	writeTalosconfig(t, f.dir)
	if err := os.WriteFile(filepath.Join(f.dir, "controlplane.yaml"),
		[]byte(fakeControlPlane), 0o600); err != nil {
		t.Fatal(err)
	}

	inner := f.rec.hooks()
	installWaits := 0
	inner.waitBootstrapReady = failFirstInstallWait(inner.waitBootstrapReady, &installWaits)
	f.opts.hooks = inner

	transcript := f.mustRun(t)

	if !f.rec.did("applyConfig") {
		t.Fatal("the config already in the state dir was never applied, so the node stays in " +
			"maintenance and every retry fails the same way")
	}
	if got := string(f.rec.payload["applyConfig"]); got != fakeControlPlane {
		t.Errorf("applied %d bytes, want the controlplane.yaml on disk\n"+
			"  reason: regenerating mints a CA the talosconfig beside it cannot authenticate", len(got))
	}
	if f.rec.did("generateConfig") {
		t.Error("regenerated the config; the new bundle's CA is not the one this node was installed with")
	}
	if !strings.Contains(transcript, "resuming") {
		t.Errorf("the resume was not announced in the transcript:\n%s", transcript)
	}
}

// A node that is NOT in maintenance is a different failure and must surface as itself.
//
// Otherwise a real install failure -- a node that took its config and is genuinely broken -- gets
// reported as a resumed apply, and the original error is lost.
func TestUpDoesNotResumeWhenTheNodeIsNotInMaintenance(t *testing.T) {
	f := newFixture(t)
	writeTalosconfig(t, f.dir)

	inner := f.rec.hooks()
	inner.waitBootstrapReady = func(context.Context, []byte, string, time.Duration) error {
		return errors.New("gave up waiting for the installed system to boot")
	}
	inner.waitMaintenance = func(context.Context, string, time.Duration) error {
		return errors.New("not in maintenance")
	}
	f.opts.hooks = inner

	err := Up(context.Background(), f.opts)
	if err == nil {
		t.Fatal("a genuinely failed install reported success")
	}
	if !strings.Contains(err.Error(), "installed system") {
		t.Errorf("the original error was replaced by the resume attempt's: %v", err)
	}
	if f.rec.did("applyConfig") {
		t.Error("applied a config to a node that is not in maintenance mode")
	}
}

func failFirstInstallWait(
	next func(context.Context, []byte, string, time.Duration) error,
	calls *int,
) func(context.Context, []byte, string, time.Duration) error {
	return func(ctx context.Context, tc []byte, ep string, d time.Duration) error {
		*calls++
		if *calls == 1 {
			return errors.New("gave up waiting for the installed system to boot")
		}
		return next(ctx, tc, ep, d)
	}
}
