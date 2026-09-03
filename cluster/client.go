package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/siderolabs/talos/pkg/machinery/client"
	clientconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	runtimeres "github.com/siderolabs/talos/pkg/machinery/resources/runtime"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// THREE PROBES THAT LOOK RIGHT AND ARE NOT. Everything in this file is shaped
// by them, so they are stated once, here, rather than three times in passing.
//
// (1) A TCP DIAL PROVES NOTHING. Every endpoint in this package is a qemu
// hostfwd, and hostfwd accepts on the HOST. The guest may have no listener, no
// kernel, no boot at all, and net.Dial still succeeds — so does a TLS-less
// port scan, and so does anything else that stops at the transport. Readiness
// here is therefore always a real Talos API CALL, never a dial, and
// TestWaitMaintenanceRejectsAnAcceptOnlyListener holds that line with a
// listener that accepts and then says nothing forever.
//
// (2) A VERSION STRING IS NOT A LIVENESS SIGNAL. `talosctl version` prints the
// CLIENT's tag from a constant compiled into the binary; it prints it happily
// with no node in sight. This package calls the Version RPC and DISCARDS the
// response: what proves the node is up is that a round trip completed against
// its apid, not anything in the payload. No probe in this file compares,
// returns or logs a version, and none may start.
//
// (3) BOOTSTRAP FIRES WHILE THE NODE IS `booting`, NOT `running`. See
// WaitBootstrapReady. There is no wait-for-stage-running function in this
// package, and that absence is deliberate.
//
// (4) AN AUTHENTICATED CALL DOES NOT PROVE THE INSTALLED SYSTEM IS SERVING.
// Once a config has been applied, the node's MAINTENANCE boot holds the cluster
// CA too, and answers with it while it installs. The credentials stop being a
// discriminator at exactly the moment the only wait that needed them runs; the
// machine's STAGE is what tells the two apart. Also see WaitBootstrapReady —
// this one cost two failed hardware bring-ups.

const (
	// probeInterval is the pause between attempts. Bring-up waits run for
	// minutes against a node that is installing and rebooting, so this is a
	// politeness interval, not a latency budget.
	probeInterval = time.Second

	// probeAttempt caps ONE attempt. Trap 1 again, from the other side: a
	// hostfwd'd port does not refuse, it HANGS — the host completes the
	// handshake and the guest never answers, so the TLS handshake sits there.
	// Without a per-attempt cap the first hung attempt swallows the whole
	// budget and the retry loop never retries. The cap is always bounded by
	// the caller's own deadline besides, because it is derived from it.
	probeAttempt = 10 * time.Second
)

// errSecretParse is the ONE place a parse failure on secret material turns
// into an error, and it deliberately drops the parser's own message.
//
// A talosconfig is five certificate authorities and a client key; a kubeconfig
// is a CA and a client key. Both are YAML, and a YAML decoder quotes what it
// choked on: machinery's reports "cannot construct !!str SEKRITx... into
// map[string]*config.Context" — seven characters of whatever scalar it was
// reading. Wrapping that with %w publishes key material to a terminal, a CI
// transcript and whatever gets pasted into an issue — the same discipline
// config_test.go imposes on test output, applied on the production side where
// nothing is there to redact afterwards.
//
// Measured, and the measurement is the reason this is a POLICY rather than a
// calculation: machinery leaks seven characters today and clientcmd's YAML ->
// JSON route leaked none of the inputs tried, but neither library promises
// either number, and one of them printing a whole scalar tomorrow is a silent
// change from "truncated" to "the private key". So the parser's message does
// not travel at all, from either of them.
//
// Errors raised AFTER a successful parse are wrapped normally: they are about
// endpoints, certificates that do not pair, and HTTP status codes, and they
// quote none of the bytes.
func errSecretParse(what string) error {
	return fmt.Errorf("the %s could not be parsed (the parser's message is withheld: it can quote "+
		"the document, and that document is a private key)", what)
}

// errNoEndpoint refuses an empty endpoint up front rather than spending the
// caller's whole timeout discovering that "" is not an address.
//
// It says what the endpoint IS and names no remedy, because the remedy differs
// by substrate and this package no longer knows which one it is looking at: a
// VM's endpoint is the host side of a port forward, an adopted node's is the
// node's own address, where there is no forward to add. A message naming one
// of the two sends half its readers to a field that does not apply to them.
func errNoEndpoint() error {
	return errors.New("no Talos API endpoint given: this is the address a client dials to reach " +
		"this node's Talos API, as host:port — e.g. 127.0.0.1:50000 for a forwarded VM, " +
		"192.168.1.50:50000 for a node reached at its own address")
}

// MaintenanceClient dials a node running in MAINTENANCE mode: booted from the
// ISO, no config applied, no cluster PKI in existence yet.
//
// Verification is OFF, and that is not a shortcut. A maintenance-mode node
// serves a self-signed certificate for CN=maintenance-service.talos.dev,
// generated on the node at boot, and it asks for no client certificate: there
// is no CA anywhere that could sign it, because the CA is in the config we
// have not sent yet. `talosctl apply-config --insecure` is the same trade for
// the same reason, and there is no trust anchor to substitute before the
// config lands.
//
// TWO OF THE THREE BOUNDS STILL HOLD, AND THE THIRD NO LONGER DOES. The node
// still holds no secrets while it is in maintenance mode, and the window still
// closes the moment ApplyConfiguration lands, after which AuthenticatedClient
// verifies properly. What is gone is loopback-by-construction: `adopt` dials
// spec.baremetal.maintenanceEndpoint, the node's own LAN address, and `up`
// dials hostForwards[].hostAddr, which the README documents as a way to publish
// on a LAN. The channel is whatever network segment lies between.
//
// So the exposure is not "nothing", it is bounded by WHO CAN SIT IN THAT PATH,
// and it has to be: applyConfiguration sends the machine config over this
// client, and that config is five certificate authorities and the machine
// token. An attacker able to answer at <endpoint>:50000 impersonates the node
// and is handed the cluster's CA private keys; one able to sit in the middle
// reads them and edits the config the real node installs. Neither is detected,
// because there is nothing here to detect it with.
//
// The operator's decision, therefore: trust the path to the node for the
// duration of an adopt. A directly-attached segment or a trusted lab LAN is
// the case this is built for; a network with hosts you would not hand the
// cluster's CA to is not, and no flag here changes that.
//
// The caller owns the returned client and must Close it.
func MaintenanceClient(ctx context.Context, endpoint string) (*client.Client, error) {
	if endpoint == "" {
		return nil, errNoEndpoint()
	}

	return client.New(ctx,
		// InsecureSkipVerify is what maintenance mode requires; see above.
		client.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec
		// Without this, machinery falls back to WithDefaultConfig() and reads
		// ~/.talos/config — an ambient file belonging to some other cluster,
		// which is exactly the "talosctl on PATH" coupling this repo links
		// machinery to avoid.
		client.WithEndpoints(endpoint),
	)
}

// AuthenticatedClient dials a node with the cluster's own PKI: it verifies the
// node's certificate against the CA in the talosconfig and presents the client
// certificate from it.
//
// That mutual authentication is also a DISCRIMINATOR, and the waits below rely
// on it: a node still in maintenance mode cannot satisfy it. Its self-signed
// certificate is not signed by this CA and it asks for no client certificate,
// so an authenticated call fails until the config has been applied, the
// installed system has booted and apid is serving with the real PKI. That is
// what makes "the authenticated API answers" a meaningful stage signal without
// asking the node what stage it is in.
//
// talosconfig is SECRET. It is never logged and never interpolated into an
// error; see errSecretParse.
//
// The caller owns the returned client and must Close it.
func AuthenticatedClient(ctx context.Context, talosconfig []byte, endpoint string) (*client.Client, error) {
	if endpoint == "" {
		return nil, errNoEndpoint()
	}

	cfg, err := clientconfig.FromBytes(talosconfig)
	if err != nil {
		return nil, errSecretParse("talosconfig")
	}

	return client.New(ctx,
		client.WithConfig(cfg),
		// The talosconfig's own endpoint list has no port, and machinery would
		// default it to apid's 50000. That is right on the node and wrong on
		// the host, where the forward may land anywhere; the caller knows
		// which port it asked qemu for, so the caller says.
		client.WithEndpoints(endpoint),
	)
}

// WaitMaintenance waits for a node to answer on the MAINTENANCE API.
//
// The probe is a Version RPC over TLS, whose RESPONSE IS DISCARDED (trap 2):
// what is being tested is that a round trip completed against apid, not
// anything it said. Reaching this state means the ISO booted far enough to
// serve the API, and the next step is to apply a config.
func WaitMaintenance(ctx context.Context, endpoint string, timeout time.Duration) error {
	c, err := MaintenanceClient(ctx, endpoint)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	return waitFor(ctx, timeout, "the Talos maintenance API at "+endpoint, func(ctx context.Context) error {
		_, err := c.Version(ctx)

		return err
	})
}

// WaitAPI waits for a node to answer on the AUTHENTICATED Talos API: the
// cluster's CA verifies its certificate and it accepts our client certificate.
//
// Same probe, same discarded response. What differs is what a success PROVES:
// maintenance mode cannot produce one, so this returning nil means the applied
// config is on disk and apid is serving with the cluster PKI.
//
// THAT IS ALL IT PROVES, and the boundary is load-bearing. apid comes up early;
// the node's other services are still starting behind it, and this probe cannot
// see any of them. A caller that needs one of them needs its own wait — see
// bootstrapWithRetry, which exists because containerd is routinely NOT up when
// this returns.
//
// talosconfig is secret and is neither logged nor placed in an error.
func WaitAPI(ctx context.Context, talosconfig []byte, endpoint string, timeout time.Duration) error {
	c, err := AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	return waitFor(ctx, timeout, "the authenticated Talos API at "+endpoint, func(ctx context.Context) error {
		_, err := c.Version(ctx)

		return err
	})
}

// WaitBootstrapReady waits for the moment `talosctl bootstrap` may be issued.
//
// TRAP 3, and it is a DEADLOCK, not a slow path. The obvious gate — wait until
// the machine reaches stage `running` — can never open: a control-plane node
// stays in `booting` until etcd is up, etcd is up only once the cluster has
// been bootstrapped, and bootstrap is the very call this gate guards. Wait for
// `running` and you wait forever, with a node that looks healthy on the console
// and a tool that looks hung.
//
// So the gate cannot be `running`. But it also cannot be "an authenticated call
// succeeded", which is what it used to be:
//
// TRAP 4, MEASURED ON HARDWARE TWICE. `apply-config` returns, and the
// MAINTENANCE BOOT restarts apid with the cluster PKI it was just handed — then
// keeps installing. An authenticated probe succeeds against that node in about
// two seconds, minutes before the machine reboots into anything. Both hardware
// bring-ups reported "api back after 2s" and both then raced the reboot: one
// bootstrapped into a node whose containerd was not up, the next got
// `connection refused` as apid went down to reboot.
//
// The claim that maintenance mode cannot satisfy the cluster PKI is true only
// BEFORE a config is applied. Afterwards it holds the CA, and this wait runs
// entirely in the window where it does — so the credentials cannot be the
// discriminator here, and the stage is.
//
// `booting` and `running` are the two stages the INSTALLED system reports, and
// accepting both is what keeps this reachable at bootstrap time while still
// excluding `maintenance`, `installing` and `rebooting`. Under QEMU the old
// gate happened to work, because a VM's install and reboot are fast enough that
// the race almost always resolved the right way — which is exactly why this was
// never seen until real hardware ran it.
func WaitBootstrapReady(ctx context.Context, talosconfig []byte, endpoint string, timeout time.Duration) error {
	c, err := AuthenticatedClient(ctx, talosconfig, endpoint)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	return waitFor(ctx, timeout, "the installed system to boot at "+endpoint, func(ctx context.Context) error {
		// EVERY failure here is a retry, and the two that matter look nothing
		// alike: a node mid-reboot refuses the connection, and a node still in
		// its maintenance boot answers perfectly and reports the wrong stage.
		status, err := safe.StateGet[*runtimeres.MachineStatus](ctx, c.COSI,
			runtimeres.NewMachineStatus().Metadata())
		if err != nil {
			return err
		}

		return checkBootstrapStage(status.TypedSpec().Stage)
	})
}

// checkBootstrapStage decides whether a stage is the installed system's own
// boot. Split out so the decision is testable without a node, because it is the
// entire content of the gate above and every other line there is plumbing.
func checkBootstrapStage(stage runtimeres.MachineStage) error {
	switch stage {
	// The installed system is up. `booting` is the normal answer and `running`
	// is what a re-run finds, and REFUSING `running` would break `up`'s
	// idempotency: step 8 has to reach the node to be told AlreadyExists.
	case runtimeres.MachineStageBooting, runtimeres.MachineStageRunning:
		return nil

	default:
		return fmt.Errorf("the node reports stage %s, which is not the installed system serving", stage)
	}
}

// WaitNodeReady waits for every registered Kubernetes node to report Ready.
//
// This is the KUBERNETES API, not the Talos one: the Talos API answers long
// before kubelet has joined, so nothing on that side can report this. It is
// the last wait in a bring-up, after bootstrap.
//
// kubeconfig is SECRET — a CA and a client key — and is neither logged nor
// placed in an error.
func WaitNodeReady(ctx context.Context, kubeconfig []byte, timeout time.Duration) error {
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return errSecretParse("kubeconfig")
	}

	nodes, err := corev1client.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building a Kubernetes client: %w", err)
	}

	return waitFor(ctx, timeout, "a Ready Kubernetes node", func(ctx context.Context) error {
		list, err := nodes.Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		// "every node is Ready" is TRUE of no nodes at all, and the API server
		// starts answering well before kubelet registers. Without this the
		// wait returns on the first successful LIST, which is the apiserver
		// coming up rather than the node joining.
		if len(list.Items) == 0 {
			return errors.New("no nodes are registered yet")
		}

		for i := range list.Items {
			if !nodeIsReady(&list.Items[i]) {
				return fmt.Errorf("node %q is not Ready yet", list.Items[i].Name)
			}
		}

		return nil
	})
}

// nodeIsReady reports whether the node's Ready condition is True.
//
// Only the Ready condition counts, and only the value True: the other
// conditions are pressure flags whose True is BAD news, and Ready itself has a
// third value, Unknown, which is what a node whose kubelet stopped
// heartbeating reports. Anything looser reads a sick node as a healthy one.
func nodeIsReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}

	return false
}

// stopWaiting wraps an error a probe wants waitFor to STOP on rather than
// retry, and waitFor returns the wrapped error unchanged.
//
// It exists because a probe has two kinds of failure and one return value could
// not tell them apart: "not yet" and "not ever". Without it, the only way to
// end a wait early is for the probe to report success, which is a lie the
// caller then has to un-tell — and the only way to report a permanent failure
// is to let the wait burn its whole budget first, so an operator watches five
// minutes elapse to be told something the first attempt already knew.
//
// The error comes back UNWRAPPED on purpose: callers match on gRPC codes
// through it (see alreadyBootstrapped), and a "gave up waiting" sentence
// around a refusal the node gave instantly would describe a timeout that never
// happened.
type stopWaiting struct{ err error }

func (s stopWaiting) Error() string { return s.err.Error() }
func (s stopWaiting) Unwrap() error { return s.err }

// waitFor polls probe until it succeeds, the timeout expires, ctx is cancelled
// or the probe returns a stopWaiting, whichever comes first.
//
// It honours BOTH deadlines because they answer different questions: timeout
// is "how long is this step allowed to take", ctx is "has the whole operation
// been called off". Deriving one context from the other means the caller's
// Ctrl-C is not stuck behind a five-minute install wait.
//
// what names the thing being waited for, in a form that reads after "waiting
// for". It ends up in the failure message together with the last probe error,
// because a bring-up tool that prints only "timed out" tells an operator
// nothing about which of four waits gave up or why.
func waitFor(ctx context.Context, timeout time.Duration, what string, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	// The one place a give-up is worded, so the two exits below cannot drift
	// apart. context.Cause is WRAPPED rather than described, so callers can
	// still ask errors.Is(err, context.DeadlineExceeded): the difference
	// between "the node is slow" and "the operator pressed Ctrl-C" survives the
	// trip.
	gaveUp := func(last error) error {
		return fmt.Errorf("gave up waiting for %s: %w (last attempt: %v)", what, context.Cause(ctx), last)
	}

	var last error

	for {
		// Derived from ctx, so it can only ever be SHORTER than what is left of
		// the budget — the cap bounds a hung attempt without ever extending the
		// caller's deadline.
		attempt, cancelAttempt := context.WithTimeout(ctx, probeAttempt)
		err := probe(attempt)

		cancelAttempt()

		if err == nil {
			return nil
		}

		// BEFORE the last-error bookkeeping below, because none of it applies:
		// there is no next attempt to preserve an error for, and the caller
		// wants the node's own refusal rather than this function's wording
		// about a budget it did not spend.
		var stop stopWaiting
		if errors.As(err, &stop) {
			return stop.err
		}

		// An attempt cut short by the deadline reports the CLOCK rather than
		// anything about the node — a hung gRPC handshake comes back as
		// "context deadline exceeded" — and letting that overwrite the 503, the
		// certificate error or the refusal the node actually gave replaces the
		// only news in the message with a restatement of the timeout the
		// message already carries. The FIRST error is always kept, though: a
		// probe that never did anything but hang has nothing else to say.
		if last == nil || ctx.Err() == nil {
			last = err
		}

		// The other half of the same problem, and the half that makes it a COIN
		// FLIP rather than an edge case. Whenever the timeout is a whole number
		// of ticks — five minutes ticking every second, which is what a
		// bring-up passes — a tick lands within microseconds of the deadline,
		// and an attempt started in that sliver never reaches the node while
		// the context is still, technically, alive: client-go's rate limiter
		// refuses on sight with "rate: Wait(n=1) would exceed context
		// deadline", which the check above therefore does not catch. Measured
		// before this guard existed: roughly one run in twenty-five.
		//
		// The budget compared against is the NEXT attempt's — it would start
		// one tick from now and needs a tick's worth of time after that to be
		// worth starting. Waiting the remainder out rather than returning early
		// keeps the wait exactly as long as the caller asked for; all that is
		// given up is a probe that could only have reported the clock.
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline)-probeInterval < probeInterval {
			<-ctx.Done()

			return gaveUp(last)
		}

		select {
		case <-ctx.Done():
			return gaveUp(last)
		case <-ticker.C:
		}
	}
}

// WaitNodeReadyAt waits for the node carrying `addr` to report Ready.
//
// SEPARATE FROM WaitNodeReady, and not a refinement of it: the two answer
// different questions and the difference is load-bearing on a join.
// WaitNodeReady asks "is every node Ready", which is the right question for a
// cluster being created — there is exactly one node and it is the one we just
// built. Asked on a JOIN it is not merely imprecise, it is satisfied by the
// wrong node: the existing control plane is already Ready, the joining node has
// not registered yet, so "every node is Ready" is TRUE and the wait returns
// before the machine this run exists to add has appeared at all. The bring-up
// then reports success for a node that may still be installing.
//
// Matched on ADDRESS rather than name because that is what the caller knows.
// A node's Kubernetes name is its hostname, which on this path is handed out by
// DHCP and adopted by the node — tinq never sees it. The address is the one
// identity the caller supplied and the certificate was issued for.
func WaitNodeReadyAt(ctx context.Context, kubeconfig []byte, addr string, timeout time.Duration) error {
	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return errSecretParse("kubeconfig")
	}

	nodes, err := corev1client.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building a Kubernetes client: %w", err)
	}

	return waitFor(ctx, timeout, fmt.Sprintf("the node at %s to be Ready", addr), func(ctx context.Context) error {
		list, err := nodes.Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		for i := range list.Items {
			node := &list.Items[i]

			if !nodeHasAddress(node, addr) {
				continue
			}

			if !nodeIsReady(node) {
				return fmt.Errorf("node %q (%s) is not Ready yet", node.Name, addr)
			}

			return nil
		}

		// NOT AN ERROR STATE, just an early one: kubelet registers the node
		// some seconds after apid starts answering, so "not there yet" is the
		// normal first answer and the message says which address is missing
		// rather than how many nodes were seen.
		return fmt.Errorf("no node with address %s has registered yet", addr)
	})
}

// nodeHasAddress reports whether any of the node's addresses equals addr.
//
// Every address type is considered, not InternalIP alone: which type a given
// address lands under is decided by the kubelet's cloud provider and node-ip
// settings, and on bare metal with no provider the same address can appear as
// InternalIP on one node and be duplicated into Hostname on another. Comparing
// all of them cannot produce a false positive here, because the caller's addr
// is the address it just installed and dialled.
func nodeHasAddress(node *corev1.Node, addr string) bool {
	for _, a := range node.Status.Addresses {
		if a.Address == addr {
			return true
		}
	}

	return false
}

// EndpointFromKubeconfig reads the API server URL out of a kubeconfig.
//
// The joined cluster's endpoint is DERIVED rather than asked for, because the
// two would be free to disagree: a manifest naming an endpoint that is not the
// one in the kubeconfig beside it produces a node pointed at a cluster whose
// credentials it does not hold, and the failure surfaces as a TLS error with
// nothing pointing at the field that caused it. The kubeconfig is already the
// thing that has to be right.
func EndpointFromKubeconfig(kubeconfig []byte) (string, error) {
	cfg, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return "", errSecretParse("kubeconfig")
	}

	// The CURRENT context's cluster, not the only one: a kubeconfig may carry
	// several, and picking by iteration order would choose a different cluster
	// on a different day.
	context, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return "", fmt.Errorf("the kubeconfig names no current context, so which of its "+
			"%d clusters this node should join cannot be decided", len(cfg.Clusters))
	}

	entry, ok := cfg.Clusters[context.Cluster]
	if !ok {
		return "", fmt.Errorf("the kubeconfig's current context names cluster %q, which it "+
			"does not define", context.Cluster)
	}

	if entry.Server == "" {
		return "", errors.New("the kubeconfig's cluster has no server address, so there is " +
			"nothing for a joining node to point at")
	}

	return entry.Server, nil
}
