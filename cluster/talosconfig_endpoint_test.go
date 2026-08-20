package cluster

import (
	"strings"
	"testing"
)

const wildcardTalosconfig = `context: venue
contexts:
    venue:
        endpoints:
            - 0.0.0.0
        ca: QUJD
`

// Measured on a node built by the previous handler and then rolled forward: its kubeconfig was
// repaired at fetch and its talosconfig was not, because step 6 reuses the file rather than
// regenerating it. Green suites never contain that node -- they build every fixture fresh.
func TestWildcardTalosEndpointIsRetargeted(t *testing.T) {
	got, changed := retargetTalosconfig([]byte(wildcardTalosconfig), "127.0.0.1")
	if !changed {
		t.Fatal("reported no change over a wildcard endpoint")
	}

	if !strings.Contains(string(got), "- 127.0.0.1") {
		t.Errorf("talosconfig = %q; endpoint not retargeted", got)
	}

	if !strings.Contains(string(got), "ca: QUJD") {
		t.Errorf("talosconfig = %q; rewrote more than the endpoint", got)
	}
}

// The control, and it guards a write: `changed` decides whether the credential file is rewritten,
// so a version that always reports true would rewrite every talosconfig on every bring-up.
func TestRealTalosEndpointIsUntouched(t *testing.T) {
	for _, in := range []string{
		"        endpoints:\n            - 10.0.2.2\n",
		"        endpoints:\n            - talos.example.com\n",
	} {
		got, changed := retargetTalosconfig([]byte(in), "127.0.0.1")
		if changed || string(got) != in {
			t.Errorf("retargetTalosconfig(%q) = %q, changed=%v; a real endpoint must survive",
				in, got, changed)
		}
	}
}

func TestTalosconfigHost(t *testing.T) {
	for endpoint, want := range map[string]string{
		"127.0.0.1:31631": "127.0.0.1",
		"0.0.0.0:31631":   "0.0.0.0",
		"[fd00::1]:50000": "fd00::1",
		"10.0.2.2":        "10.0.2.2",
		"":                "",
	} {
		if got := talosconfigHost(endpoint); got != want {
			t.Errorf("talosconfigHost(%q) = %q, want %q", endpoint, got, want)
		}
	}
}
