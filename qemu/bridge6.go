package qemu

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// bridgeSet publishes QEMU's IPv4-only host forwards on IPv6.
//
// QEMU user-mode networking has no IPv6 hostfwd. On a single-stack IPv6 host the only IPv4 address
// in the namespace is 127.0.0.1, so a forwarded guest port is reachable from inside that namespace
// and from nowhere else: the VM runs, reports Running, and cannot be talked to.
//
// The listener is tcp6, never tcp. Go's "tcp" on [::] is dual-stack and would also claim
// 0.0.0.0:PORT, which collides with the address QEMU is already holding.
//
// Opt-in via TINQ_BRIDGE_V6, because [::] is every interface: on a laptop this would publish a
// guest port to the LAN, and that must be a decision rather than a side effect of running on a
// machine that happens to lack IPv4.
type bridgeSet struct {
	mu   sync.Mutex
	open map[int]net.Listener
}

func newBridgeSet() *bridgeSet {
	return &bridgeSet{open: map[int]net.Listener{}}
}

// ensure publishes port on [::]:port, forwarding to 127.0.0.1:port. It is idempotent: the reconcile
// loop calls it every tick for every running machine.
func (b *bridgeSet) ensure(port int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.open[port]; ok {
		return nil
	}
	l, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		return fmt.Errorf("bridge :%d: %w", port, err)
	}
	b.open[port] = l
	go b.serve(l, port)
	log.Printf("bridging [::]:%d -> 127.0.0.1:%d", port, port)
	return nil
}

func (b *bridgeSet) serve(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return // closed
		}
		go pipe(c, port)
	}
}

func pipe(in net.Conn, port int) {
	defer in.Close()
	out, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// The guest is not answering yet. Closing is the honest response: a held-open connection
		// would look to the caller like a slow service rather than an absent one.
		return
	}
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(out, in); done <- struct{}{} }()
	go func() { io.Copy(in, out); done <- struct{}{} }()
	<-done
}

func (b *bridgeSet) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.open)
}

// prune closes bridges for ports no longer wanted, so a destroyed machine does not leave a listener
// answering on a port the next machine may be given.
func (b *bridgeSet) prune(want map[int]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for port, l := range b.open {
		if !want[port] {
			l.Close()
			delete(b.open, port)
			log.Printf("bridge [::]:%d closed", port)
		}
	}
}

func (b *bridgeSet) closeAll() {
	b.prune(map[int]bool{})
}

// bridges is the process-wide set. A bridge belongs to the process, not to the machine: qemu is
// detached and survives this binary restarting, so the listeners are re-established by Observe on
// the next tick rather than assumed to exist.
var bridges = newBridgeSet()

// bridgeForwards publishes a running machine's host forwards on IPv6.
//
// Gated on TINQ_BRIDGE_V6 because [::] is every interface: on a laptop this would put a guest's
// Talos API on the LAN. In a pod netns it is the pod's own address and nothing more.
func bridgeForwards(m *unstructured.Unstructured) {
	if os.Getenv("TINQ_BRIDGE_V6") == "" {
		return
	}
	for _, hf := range nestedSlice(m, "spec", "hostForwards") {
		h, _ := hf.(map[string]interface{})
		hp := toInt(h["hostPort"])
		if hp <= 0 {
			continue
		}
		if err := bridges.ensure(hp); err != nil {
			log.Printf("%s: %v", m.GetName(), err)
		}
	}
}
