package cluster

import (
	"net"
	"net/url"
	"strings"
)

// wildcardHosts are BIND addresses: they say where a server listens, never where to connect.
var wildcardHosts = map[string]bool{"0.0.0.0": true, "::": true, "[::]": true}

// retargetKubeconfig rewrites the kubeconfig's `server:` host when it is a wildcard.
//
// Talos stamps the endpoint from the machine config it was given, so a wildcard control-plane
// endpoint yields `server: https://0.0.0.0:33131` -- syntactically fine, EOF when dialled. Applied
// at FETCH, not only at generation: a node configured before this fix keeps handing out the old
// value. See TestWildcardServerIsRetargeted.
func retargetKubeconfig(kubeconfig []byte, host string) []byte {
	if host == "" || wildcardHosts[host] {
		return kubeconfig
	}

	out := make([]string, 0, 64)

	for _, line := range strings.Split(string(kubeconfig), "\n") {
		out = append(out, retargetServerLine(line, host))
	}

	return []byte(strings.Join(out, "\n"))
}

// retargetServerLine rewrites one `server: <url>` line, keeping indentation, scheme and port.
func retargetServerLine(line, host string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "server:") {
		return line
	}

	u, err := url.Parse(strings.TrimSpace(strings.TrimPrefix(trimmed, "server:")))
	if err != nil || u.Host == "" {
		return line
	}

	h, port, err := net.SplitHostPort(u.Host)
	if err != nil || !wildcardHosts[h] {
		return line
	}

	u.Host = net.JoinHostPort(host, port)

	return line[:len(line)-len(trimmed)] + "server: " + u.String()
}

// kubeconfigHost is the host part of a kube endpoint URL, or "" when it has none.
func kubeconfigHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}

	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		return h
	}

	return u.Host
}
