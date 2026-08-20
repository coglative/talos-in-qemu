package qemu

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// hostAddr is a BIND address and was being reused as a DESTINATION. Measured: the venue's generated
// kubeconfig read `server: https://0.0.0.0:33131`, and kubectl against it failed with
// `Get "https://0.0.0.0:33131/openapi/v2": EOF` -- from the handler, before any delivery mechanism
// exists. Rewriting only the host to 127.0.0.1 makes the same file work.
func TestWildcardBindIsNotAdvertised(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "[::]"} {
		if got := advertised(bind); got == bind {
			t.Errorf("advertised(%q) = %q; a wildcard bind cannot be dialled", bind, got)
		}
	}
}

// The control. Without it advertised could return a constant and the test above would still pass,
// while every machine advertised loopback regardless of where it was actually reachable.
func TestRealAddressesArePassedThrough(t *testing.T) {
	for _, bind := range []string{"127.0.0.1", "10.0.2.2", "192.168.1.5", "fd00::1"} {
		if got := advertised(bind); got != bind {
			t.Errorf("advertised(%q) = %q; a stated address must survive", bind, got)
		}
	}
}

// The two sides of hostAddr must stay separate: qemu still BINDS the wildcard, and only the DIAL
// side is rewritten. Rewriting both would make the venue's ports pod-local and unreachable.
func TestBindSideReadsHostAddrRaw(t *testing.T) {
	doc := "spec:\n  hostForwards:\n    - hostPort: 31631\n      guestPort: 50000\n" +
		"      hostAddr: 0.0.0.0\n    - hostPort: 33131\n      guestPort: 6443\n" +
		"      hostAddr: 0.0.0.0\n"
	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
		t.Fatal(err)
	}
	m := &unstructured.Unstructured{Object: obj}

	netdev := netdevArg(m)
	for _, want := range []string{"hostfwd=tcp:0.0.0.0:31631-:50000", "hostfwd=tcp:0.0.0.0:33131-:6443"} {
		if !strings.Contains(netdev, want) {
			t.Errorf("netdevArg = %q; lost the wildcard bind %q", netdev, want)
		}
	}
	if got := talosEndpoint(m); got != "127.0.0.1:31631" {
		t.Errorf("talosEndpoint = %q; want the dialable form", got)
	}
	if got := kubeEndpoint(m); got != "https://127.0.0.1:33131" {
		t.Errorf("kubeEndpoint = %q; want the dialable form", got)
	}
}
