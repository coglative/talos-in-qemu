// Package driverkit is the half that every XSite driver repeats.
//
// Factored AFTER two drivers existed (provider-hvf, provider-gcpmin), not
// before. Extracting a skeleton from one instance is guessing about which parts
// are shared; extracting it from two is reading.
//
// What is here is the GC CONTRACT, which is identical everywhere:
//
//	list -> hold a finalizer -> observe the external system -> converge on the
//	     desired power state -> destroy BEFORE dropping the finalizer
//
// What is deliberately NOT here is anything a substrate decides for itself: its
// SCC shape, how it tags artifacts with the site, how it resolves a neutral
// profile name. Pulling those up would be exactly the lowest-common-denominator
// flattening that hides each provider's orphan classes (ARCHITECTURE.md D6).
package driverkit

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// State is what the EXTERNAL SYSTEM reports about a resource, never what we
// wish were true.
//
// Three values, not two, because "the disks exist but nothing is running" is a
// real and now-ordinary condition — it is what a deliberately stopped machine
// looks like, and it must not be confused with "never created".
//
// This does relax the letter of Observe's old contract, which said never to
// consult a local state file. The rule worth keeping is narrower than that
// sentence: never report a dead thing as Ready. talosctl's cluster show
// reported a long-dead cluster as present AND USABLE; reporting one as present
// and STOPPED claims nothing. The invariant in fact gets stronger here, because
// Running now demands a VERIFIED process rather than a bare pid.
type State int

const (
	Absent  State = iota // no disks: never created, or destroyed
	Stopped              // disks exist, nothing is running
	Running              // a verified process for THIS machine is alive
)

func (s State) String() string {
	switch s {
	case Stopped:
		return "Stopped"
	case Running:
		return "Running"
	default:
		return "Absent"
	}
}

// Driver is the substrate-specific half: four verbs against one external
// system — Observe, Create, Stop, Destroy. Everything else in this package is
// the same for all of them.
type Driver interface {
	// Observe asks the EXTERNAL SYSTEM what state the resource is in, and
	// returns status fields to publish. It must not report Running on the
	// strength of a file: a pidfile is a claim, and this interface exists
	// because talosctl's cluster show believed one about a long-dead cluster.
	//
	// THAT RULE BINDS A DRIVER THAT OWNS ITS RESOURCE'S LIFECYCLE, and is not
	// relaxed for one: if you started it, you can verify it, and a file
	// standing in for that verification is the exact bug above.
	//
	// A driver may also be handed a resource it did NOT create and cannot
	// power-cycle — the qemu driver's adopted baremetal machines are the case
	// in this repo. It then has no process to verify and no cheap truthful
	// liveness answer, since Observe is host-side, read-only and runs every
	// tick. Such a driver is expected to report Running and to publish an
	// address the operator can ask instead. Not because it knows the thing is
	// up, but because Absent and Stopped are the two answers plan() turns into
	// a Create against a machine it must never touch, and a driver with no
	// work to do must converge the loop on doing none.
	//
	// THE COST IS BORNE HERE: publish marks Ready=True on state == Running, so
	// such a resource reads Ready even while physically powered off. That is
	// the price of not creating hardware, paid in a status field, rather than
	// in a Create against it. Keep it in view — it is why the exception is
	// written down instead of left in the driver.
	Observe(ctx context.Context, m *unstructured.Unstructured) (state State, status map[string]interface{}, err error)

	// Create brings the resource to Running from EITHER Absent or Stopped, so
	// it is as much "start" as "create". The name is kept for compatibility,
	// not for accuracy — this comment is the accuracy.
	//
	// From Absent it provisions. From Stopped it restarts what is already
	// there, reusing existing artifacts rather than recreating them; for the
	// qemu driver that means the installed OS and the user's PVCs survive.
	// Must be safe to retry after a partial failure: the next tick calls it
	// again.
	Create(ctx context.Context, m *unstructured.Unstructured) error

	// Stop takes the resource from Running to Stopped WITHOUT destroying
	// anything. Idempotent: already stopped, or never created, is success.
	//
	// It must ask the resource to stop, not merely kill whatever is hosting it.
	// For a VM those are different events — the second is a power cut the guest
	// never learns about — and the whole point of separating Stop from Destroy
	// is that the disks are still wanted afterwards.
	Stop(ctx context.Context, m *unstructured.Unstructured) error

	// Destroy removes it, INCLUDING every artifact in its SCC. Must be
	// idempotent: already-gone is success, or a repeated delete tick wedges the
	// finalizer forever. Returning an error BLOCKS deletion — that is the point.
	// A teardown that reports success while stranding a resource is the leak the
	// whole design exists to prevent.
	Destroy(ctx context.Context, m *unstructured.Unstructured) error
}

type Config struct {
	GVR       schema.GroupVersionResource
	Finalizer string
	Interval  time.Duration

	// NodeName is the node this driver actuates for, and it partitions the machines it will touch.
	// Empty keeps the original behaviour of reconciling everything listed, which is right for a
	// single process that owns every machine. Set it when more than one replica can see the same
	// machine: Run's comment explains why serial reconciliation stops being sufficient there.
	// The claim is first-writer-wins on status.node, and a machine another node holds is skipped.
	NodeName string
}

// Run is the reconcile loop. It owns the finalizer dance and status publishing
// so no driver can get that half subtly wrong.
//
// DEFERRED: reconciliation is SERIAL. One machine that is stopping holds the
// loop for as long as its stop takes — for the qemu driver, up to ~85s (15s
// shutdown RPC + 60s graceful power-off + 5s SIGTERM + 5s SIGKILL) — and every
// other machine waits it out. That is a real stall, and it is knowingly not
// fixed:
//
//   - There is one machine. Multi-node is blocked on QEMU user-mode networking
//     (SLIRP: one NIC, no VM-to-VM link) and is a stated non-goal in the README,
//     so the queue this would relieve does not exist yet.
//   - The fix is not "go reconcile(...)". Concurrent reconciliation needs
//     per-key locking to guarantee one machine is never reconciled twice at
//     once. Without it, two ticks overlap and two qemu processes run against a
//     single state dir — which the qemu driver's own Boot closure calls
//     corrupting the disk they share (cmd/tinq/main.go, "Starting a second qemu
//     against one state dir"). A stall is recoverable; that is not.
//
// The trigger is a CONDITION, not a date: revisit when a second machine can
// exist. Until then a slow neighbour is the cheaper failure.
//
// Cancellation is NOT part of that deferral and is already handled: the driver
// verbs take this ctx and must honour it, so a Ctrl-C mid-stop returns within a
// poll interval rather than at the end of the budget. The ~85s above is the
// stall one machine imposes on another, not the delay an operator sees.
func Run(ctx context.Context, cfg Config, d Driver) error {
	kubeconfig := flag.Lookup("kubeconfig").Value.String()
	rc, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("kubeconfig: %w", err)
	}
	dc, err := dynamic.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}

	log.Printf("%s driver up — reconciling every %s", cfg.GVR.Resource, cfg.Interval)
	for {
		list, err := dc.Resource(cfg.GVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("list: %v", err)
		} else {
			for i := range list.Items {
				m := &list.Items[i]
				if err := reconcile(ctx, dc, cfg, d, m); err != nil {
					log.Printf("%s: %v", m.GetName(), err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.Interval):
		}
	}
}

func reconcile(ctx context.Context, dc dynamic.Interface, cfg Config, d Driver, m *unstructured.Unstructured) error {
	ri := dc.Resource(cfg.GVR)

	// NOT MINE, INCLUDING ITS DELETION. Run lists with no selector, so every handler sees every
	// machine; this check kept three nodes from each building a VM for one CR, and it used to sit
	// BELOW the delete branch. So on a delete every node ran Destroy and the first to finish
	// released the finalizer -- truthfully, about its own disk, where there was nothing -- and the
	// node actually holding the VM never got the chance. See TestReconcileDoesNotDestroyAMachine-
	// AnotherNodeHolds for the measurement.
	//
	// An UNCLAIMED machine is deliberately not skipped: no node holds a VM for it, so no Destroy
	// has anything to do, and declining here would trade a leak for a wedged finalizer.
	if cfg.NodeName != "" {
		holder, _, err := unstructured.NestedString(m.Object, "status", "node")
		if err != nil {
			return fmt.Errorf("read status.node: %w", err)
		}

		if holder != "" && holder != cfg.NodeName {
			return nil
		}
	}

	// DELETE FIRST. Destroy must succeed before the finalizer goes, so a failed
	// teardown blocks deletion instead of leaking silently.
	if m.GetDeletionTimestamp() != nil {
		if err := d.Destroy(ctx, m); err != nil {
			return fmt.Errorf("destroy (deletion BLOCKED, which is correct): %w", err)
		}
		// CLAIM ONLY WHAT nil PROMISES, which is "the driver has no teardown
		// work left", not "the resource is gone". Those coincide for a driver
		// that owns its resource's lifecycle and do not for one that does not:
		// the qemu driver's Destroy on an adopted machine deliberately removes
		// nothing and says so on the line above, and "bm0: destroyed" printed
		// underneath is the operator-facing summary contradicting it.
		//
		// Softened here rather than fixed with an outcome value returned from
		// Destroy: an extra return would change the Driver interface for every
		// driver to carry one driver's special case, and driverkit must not
		// learn what "baremetal" means. A driver that did something noteworthy
		// already has a log line for it; the loop's job is only to say the
		// finalizer is going, which is the part the loop actually did.
		log.Printf("%s: teardown reported complete, releasing the finalizer", m.GetName())
		_, err := ri.Patch(ctx, m.GetName(), "application/merge-patch+json",
			[]byte(`{"metadata":{"finalizers":[]}}`), metav1.PatchOptions{})
		return err
	}

	if cfg.NodeName != "" {
		holder, _, err := unstructured.NestedString(m.Object, "status", "node")
		if err != nil {
			return fmt.Errorf("read status.node: %w", err)
		}

		if holder == "" {
			body := fmt.Sprintf(`{"status":{"node":%q}}`, cfg.NodeName)
			if _, err := ri.Patch(ctx, m.GetName(), "application/merge-patch+json",
				[]byte(body), metav1.PatchOptions{}, "status"); err != nil {
				return fmt.Errorf("claim: %w", err)
			}
		}
	}

	if !hasFinalizer(m, cfg.Finalizer) {
		body := fmt.Sprintf(`{"metadata":{"finalizers":["%s"]}}`, cfg.Finalizer)
		_, err := ri.Patch(ctx, m.GetName(), "application/merge-patch+json", []byte(body), metav1.PatchOptions{})
		return err // re-read next tick
	}

	state, st, err := d.Observe(ctx, m)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	desired := desiredPowerState(m)
	create, stop := plan(state, desired)

	switch {
	case create:
		if err := d.Create(ctx, m); err != nil {
			_ = publish(ctx, ri, m, nil, state, false, false, "CreateFailed", err.Error())
			return fmt.Errorf("create: %w", err)
		}
		log.Printf("%s: created", m.GetName())
		return nil // next tick observes it
	case stop:
		if err := d.Stop(ctx, m); err != nil {
			_ = publish(ctx, ri, m, st, state, false, false, "StopFailed", err.Error())
			return fmt.Errorf("stop: %w", err)
		}
		// SAME RULE AS THE DELETE PATH ABOVE, and the reachable half of it.
		// nil from Stop promises "the driver has no stop work left", not "the
		// machine is powered off". A driver handed a resource it did not
		// create cannot power-cycle it: it changes nothing, says so on its own
		// line, and returns nil because an error here would spin the tick
		// forever. "bm0: stopped" printed underneath is the loop contradicting
		// the driver, and spec.powerState: Stopped keeps asking, so it does it
		// on every tick.
		//
		// Reachable where the create arm above is not: such a driver Observes
		// Running, so plan() never asks it to create and always asks it to
		// stop. Softened rather than fixed with an outcome value, for the
		// reason the delete path gives — driverkit must not learn what any one
		// driver's special case means.
		log.Printf("%s: stop reported complete", m.GetName())
		return nil // next tick observes it
	}

	// Converged. Ready reflects USABILITY, which a deliberately stopped machine
	// does not have — so it reports Ready=False with reason Stopped, beside
	// Synced=True. Without that split, "stopped on purpose" and "failed to
	// start" look identical in kubectl, and one of them is an incident.
	return publish(ctx, ri, m, st, state, true, state == Running, state.String(),
		"converged on spec.powerState="+desired)
}

// desiredPowerState reads spec.powerState, defaulting to Running so every
// existing manifest keeps its current meaning.
func desiredPowerState(m *unstructured.Unstructured) string {
	if s := Str(m, "spec", "powerState"); s != "" {
		return s
	}
	return "Running"
}

// plan is the transition table from the design, kept as a pure function so it
// is testable without an API server.
//
// Absent+Stopped converges by creating and then stopping on the next tick,
// rather than refusing. Talos cannot be installed without booting, so "exists
// but never booted" is empty disks impersonating a machine; converging costs
// one wasted boot in a rare case, while refusing would leave the resource
// permanently un-converged, which is not how a controller should behave.
func plan(observed State, desired string) (create, stop bool) {
	switch {
	case desired == "Stopped" && observed == Running:
		return false, true
	case desired == "Stopped" && observed == Absent:
		return true, false // converge: create now, stop next tick
	case desired == "Stopped":
		return false, false // already Stopped
	case observed == Running:
		return false, false // wants Running, is Running
	default:
		return true, false // wants Running, is Absent or Stopped
	}
}

// publish writes status. synced and ready are SEPARATE because they answer
// different questions — see statusPatch — and a caller that collapses them
// hides exactly the case this change exists to distinguish.
func publish(ctx context.Context, ri dynamic.ResourceInterface, m *unstructured.Unstructured,
	st map[string]interface{}, observed State, synced, ready bool, reason, msg string) error {
	b := statusPatch(m.GetGeneration(), st, observed, synced, ready, reason, msg)
	_, err := ri.Patch(ctx, m.GetName(), "application/merge-patch+json", b, metav1.PatchOptions{}, "status")
	return err
}

// statusPatch builds the status body. Pure, and split from the Patch call, so
// the Synced/Ready matrix is testable without an API server — the same reason
// plan is a function rather than an if-tree inside reconcile. A failed verb
// reporting Synced=True would be a lie, and a lie no test could catch is one
// that ships.
func statusPatch(generation int64, st map[string]interface{}, observed State,
	synced, ready bool, reason, msg string) []byte {
	status := map[string]interface{}{}
	for k, v := range st {
		status[k] = v
	}
	status["powerState"] = observed.String()
	status["observedGeneration"] = generation
	now := time.Now().UTC().Format(time.RFC3339)
	status["conditions"] = []interface{}{
		// Synced: the reconciler applied spec without error. A machine that is
		// stopped BECAUSE THAT IS WHAT WAS ASKED FOR is fully synced.
		map[string]interface{}{
			"type": "Synced", "status": boolCondition(synced), "reason": reason,
			"message": msg, "lastTransitionTime": now,
		},
		// Ready: the resource is usable. Stopped is not usable, and says so.
		map[string]interface{}{
			"type": "Ready", "status": boolCondition(ready), "reason": reason,
			"message": msg, "lastTransitionTime": now,
		},
	}
	b, _ := json.Marshal(map[string]interface{}{"status": status})
	return b
}

// boolCondition renders a condition status. Kubernetes conditions are tri-state
// strings, not booleans, and "true" lowercase is not one of the three.
func boolCondition(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func hasFinalizer(m *unstructured.Unstructured, f string) bool {
	for _, x := range m.GetFinalizers() {
		if x == f {
			return true
		}
	}
	return false
}

// Kubeconfig registers the flag every driver needs. Call before flag.Parse.
func Kubeconfig() {
	flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "control plane kubeconfig")
}

// Str reads a string out of a resource, empty if absent.
func Str(m *unstructured.Unstructured, path ...string) string {
	v, _, _ := unstructured.NestedString(m.Object, path...)
	return v
}
