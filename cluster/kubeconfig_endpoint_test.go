package cluster

import (
	"strings"
	"testing"
)

const wildcardKubeconfig = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: QUJD
    server: https://0.0.0.0:33131
  name: venue
`

// Measured on a live venue: the kubeconfig read `server: https://0.0.0.0:33131` and kubectl failed
// with `Get "https://0.0.0.0:33131/openapi/v2": EOF`. Rewriting only the host makes the same file
// work, so that is the whole repair.
func TestWildcardServerIsRetargeted(t *testing.T) {
	got := string(retargetKubeconfig([]byte(wildcardKubeconfig), "127.0.0.1"))
	if !strings.Contains(got, "server: https://127.0.0.1:33131") {
		t.Errorf("kubeconfig = %q; wildcard server not retargeted", got)
	}

	if strings.Contains(got, "0.0.0.0") {
		t.Errorf("kubeconfig = %q; still carries the bind address", got)
	}

	if !strings.Contains(got, "certificate-authority-data: QUJD") {
		t.Errorf("kubeconfig = %q; rewrote more than the server line", got)
	}
}

// The control. A kubeconfig that already names a reachable address must come back byte-identical --
// otherwise the repair would retarget every node to loopback regardless of where it lives.
func TestRealServerIsUntouched(t *testing.T) {
	for _, in := range []string{
		"    server: https://10.0.2.2:6443\n",
		"    server: https://kube.example.com:6443\n",
		"    server: https://[fd00::1]:6443\n",
	} {
		if got := string(retargetKubeconfig([]byte(in), "127.0.0.1")); got != in {
			t.Errorf("retargetKubeconfig(%q) = %q; a real server must survive", in, got)
		}
	}
}

// A wildcard replacement is not a repair, and applying one would swap one unreachable address for
// another while reporting success.
func TestWildcardReplacementIsRefused(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::"} {
		got := string(retargetKubeconfig([]byte(wildcardKubeconfig), host))
		if got != wildcardKubeconfig {
			t.Errorf("retargetKubeconfig(_, %q) rewrote to %q; want no change", host, got)
		}
	}
}

func TestKubeconfigHost(t *testing.T) {
	for endpoint, want := range map[string]string{
		"https://127.0.0.1:33131": "127.0.0.1",
		"https://0.0.0.0:33131":   "0.0.0.0",
		"https://[fd00::1]:6443":  "fd00::1",
		"https://kube.example":    "kube.example",
		"":                        "",
		"not a url":               "",
	} {
		if got := kubeconfigHost(endpoint); got != want {
			t.Errorf("kubeconfigHost(%q) = %q, want %q", endpoint, got, want)
		}
	}
}
