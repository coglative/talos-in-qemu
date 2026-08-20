package qemu

import "testing"

// The guest's IPv6 stack is opt-in, and absent by default.
//
// A guest handed an IPv6 default route will prefer it. On a laptop with filtered IPv6 that turns a
// working bring-up into a hanging one, and nothing would connect the hang to this flag -- so the
// default must stay exactly what it was.
func TestGuestIPv6IsOptIn(t *testing.T) {
	t.Setenv("TINQ_GUEST_IPV6", "")
	if got := guestIPv6(); got != "" {
		t.Fatalf("unset must add nothing to the netdev; got %q", got)
	}
	t.Setenv("TINQ_GUEST_IPV6", "1")
	if got := guestIPv6(); got != ",ipv6=on" {
		t.Fatalf("set must enable slirp IPv6; got %q", got)
	}
}
