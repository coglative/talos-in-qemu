package cluster

import (
	"strings"
	"testing"
)

// A KUBECONFIG THAT ONLY WORKS ON THE NODE IS NOT A DELIVERABLE. The file Talos hands back names
// the host side of a forward: right for the handler, unreachable elsewhere. Without this, every
// carrier must rewrite it AND know the naming convention -- a carrier requiring its reader to know
// it. Rewriting here means a carrier only has to CARRY.
func TestKubeconfigCanBeAdvertisedUnderAName(t *testing.T) {
	in := "    server: https://127.0.0.1:33131\n"

	got := string(advertiseKubeconfig([]byte(in), "venue.ws-x.svc.cluster.local"))
	if !strings.Contains(got, "server: https://venue.ws-x.svc.cluster.local:33131") {
		t.Errorf("kubeconfig = %q; the name did not replace the host", got)
	}
}

// THE PORT SURVIVES: a name with the port dropped resolves correctly and connects to nothing.
func TestAdvertisedKubeconfigKeepsThePort(t *testing.T) {
	for _, port := range []string{"33131", "6443", "31000"} {
		in := "    server: https://127.0.0.1:" + port + "\n"

		got := string(advertiseKubeconfig([]byte(in), "venue.ws-x"))
		if !strings.Contains(got, ":"+port) {
			t.Errorf("port %q lost: %q", port, got)
		}
	}
}

// The control: with no name asked for the file is byte-identical.
func TestNoAdvertiseNameLeavesTheKubeconfigAlone(t *testing.T) {
	in := "    server: https://127.0.0.1:33131\n"

	if got := string(advertiseKubeconfig([]byte(in), "")); got != in {
		t.Errorf("rewrote with no name asked for: %q", got)
	}
}

// THE FIXTURE CARRIES `proxy-url` ON PURPOSE: it is the only other kubeconfig field parsing as a
// URL with a host, so a loosened match would point the client at the venue as its proxy. The first
// fixture had no other rewritable line, so this asserted nothing -- a check that could not fail,
// inside the test written to prove the rewrite was narrow.
func TestAdvertiseRewritesOnlyTheServer(t *testing.T) {
	in := "clusters:\n- cluster:\n    certificate-authority-data: QUJD\n" +
		"    proxy-url: https://proxy.example:8080\n" +
		"    server: https://127.0.0.1:33131\n  name: venue\n"

	got := string(advertiseKubeconfig([]byte(in), "venue.ws-x"))

	for _, want := range []string{
		"certificate-authority-data: QUJD",
		"proxy-url: https://proxy.example:8080",
		"name: venue",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rewrote %q away; only the server line may change:\n%s", want, got)
		}
	}
}
