package qemu

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// crdPath is relative because the CRD is part of THIS repo and the test is only
// meaningful against the checked-out copy — there is no installed artifact to
// point at, and resolving it any other way would let the test pass while the
// file in the tree is broken.
const crdPath = "../crd/talosmachine.yaml"

// The CRD is DATA, so nothing in `go build` or `go test` had an opinion about
// it: someone could drop a validation rule or rename a spec.baremetal field and
// the whole suite would stay green. The first sign would be a rejected `kubectl
// apply` on a machine that was supposed to work, or worse, an accepted one that
// was not. This test is the cheapest thing that fails earlier than that.
//
// It asserts STRUCTURE, not semantics. Evaluating the CEL would mean promoting
// cel-go from an indirect dependency to a direct one, and evaluation is not
// where the regression lives — a rule that gets edited or deleted is. Presence,
// and which fields each rule still names, is exactly the part an edit breaks,
// and sigs.k8s.io/yaml (already a direct dependency) is enough to see it.
func TestCRDGuardsWhatTheGoCodeAssumes(t *testing.T) {
	raw, err := os.ReadFile(crdPath)
	if err != nil {
		t.Fatalf("read the CRD: %v", err)
	}

	var crd map[string]interface{}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatalf("the CRD does not parse as YAML: %v", err)
	}

	versions, ok := crdDig(t, crd, "spec", "versions").([]interface{})
	if !ok || len(versions) != 1 {
		t.Fatalf("expected exactly one version in the CRD, got %v", versions)
	}

	specSchema := crdMap(t, crdDig(t, crdMap(t, versions[0], "versions[0]"),
		"schema", "openAPIV3Schema", "properties", "spec"), "the spec schema")

	// `required` MUST STAY RELAXED. Putting image/cpu/memory/disk back would
	// make every baremetal machine unsubmittable — the CEL rule below is what
	// holds the VM half of that constraint now.
	if got, want := crdStrings(t, specSchema["required"], "spec.required"), []string{"site", "role"}; !reflect.DeepEqual(got, want) {
		t.Errorf("spec.required is %v, want %v — a baremetal machine has none of the build fields", got, want)
	}

	// Each rule is found by the substring no other rule in the file carries,
	// then checked for every field it must still name. Matching the whole
	// expression would fail on a harmless reformat; matching only the id would
	// not notice a field quietly dropped out of the disjunction.
	rules := []struct {
		id    string
		names []string
		why   string
	}{
		{
			id:    "has(self.baremetal) ||",
			names: []string{"has(self.image)", "has(self.cpu)", "has(self.memory)", "has(self.disk)"},
			why:   "without it a VM with no disk is submittable, which is what `required` used to prevent",
		},
		{
			id: "!(has(self.baremetal) &&",
			names: []string{
				"has(self.hostForwards)", "has(self.image)", "has(self.cpu)",
				"has(self.memory)", "has(self.disk)", "has(self.dataDisk)",
			},
			why: "each field it stops naming becomes accepted beside spec.baremetal and then silently ignored",
		},
	}

	var exprs []string
	for i, r := range crdList(t, specSchema["x-kubernetes-validations"], "spec.x-kubernetes-validations") {
		exprs = append(exprs, crdString(t, crdMap(t, r, fmt.Sprintf("rule[%d]", i))["rule"]))
	}

	for _, want := range rules {
		expr := ""
		for _, e := range exprs {
			if strings.Contains(e, want.id) {
				expr = e
				break
			}
		}

		if expr == "" {
			t.Errorf("no x-kubernetes-validations rule contains %q — %s", want.id, want.why)
			continue
		}

		for _, n := range want.names {
			if !strings.Contains(expr, n) {
				t.Errorf("the rule %q no longer names %s — %s", want.id, n, want.why)
			}
		}
	}

	baremetal := crdMap(t, crdDig(t, specSchema, "properties", "baremetal"), "spec.baremetal")

	if got, want := crdStrings(t, baremetal["required"], "spec.baremetal.required"), []string{"maintenanceEndpoint"}; !reflect.DeepEqual(got, want) {
		t.Errorf("spec.baremetal.required is %v, want %v — adopt.go cannot dial a node with no address", got, want)
	}

	props := crdMap(t, baremetal["properties"], "spec.baremetal.properties")

	// required is KEY PRESENCE, so `maintenanceEndpoint: ""` satisfies it and
	// reaches adopt.go, which then refuses it. minLength is what makes the
	// schema mean what that `required` line reads as. Reported rather than
	// fatal, so losing it does not hide the field checks below.
	if got := fmt.Sprint(crdMap(t, props["maintenanceEndpoint"], "spec.baremetal.maintenanceEndpoint")["minLength"]); got != "1" {
		t.Errorf("spec.baremetal.maintenanceEndpoint minLength is %s, want 1 — `required` alone accepts an empty string", got)
	}

	// Every field cmd/tinq/adopt.go reads out of the block. A schema missing one
	// of these prunes it on the way through an apiserver, so the value the
	// operator wrote never arrives.

	for _, f := range []string{"maintenanceEndpoint", "systemDiskSerial", "systemDiskWWID", "dataDiskSerial", "ephemeralMaxSize", "consoleArg", "talosVersion", "network"} {
		if _, ok := props[f]; !ok {
			t.Errorf("spec.baremetal.%s is missing from the schema, but adopt.go reads it", f)
		}
	}

	// The network block is ALL-OR-NOTHING. A schema that lets three of the four
	// through produces a node with a static address and no resolver, or one
	// whose NIC was never named — both of which install and then go silent.
	network := crdMap(t, crdDig(t, props, "network"), "spec.baremetal.network")

	if got, want := crdStrings(t, network["required"], "spec.baremetal.network.required"),
		[]string{"address", "gateway", "nameservers", "hardwareAddr"}; !reflect.DeepEqual(got, want) {
		t.Errorf("spec.baremetal.network.required is %v, want %v — a half-configured static "+
			"network is a node that installs and never answers", got, want)
	}

	netProps := crdMap(t, network["properties"], "spec.baremetal.network.properties")

	for _, f := range []string{"address", "gateway", "nameservers", "hardwareAddr"} {
		if _, ok := netProps[f]; !ok {
			t.Errorf("spec.baremetal.network.%s is missing from the schema, but adopt.go reads it", f)
		}
	}

	// nameservers is a LIST, and `required` on a list is satisfied by an empty
	// one. minItems is what makes that line mean what it reads as — the same
	// gap minLength closes on maintenanceEndpoint.
	if got := fmt.Sprint(crdMap(t, netProps["nameservers"], "…network.nameservers")["minItems"]); got != "1" {
		t.Errorf("spec.baremetal.network.nameservers minItems is %s, want 1 — `required` alone "+
			"accepts an empty list, and a node with no resolver cannot pull an image", got)
	}

	// spec.registries is the ONLY way to configure a mirror — there is no flag
	// for it — so a field pruned by the apiserver is not a validation error, it
	// is a node that silently pulls from the internet and a config that looks
	// applied. Same failure as the baremetal block above, one field over.
	items := crdMap(t, crdDig(t, specSchema, "properties", "registries", "items"), "spec.registries.items")

	if got, want := crdStrings(t, items["required"], "spec.registries.items.required"),
		[]string{"host", "endpoint"}; !reflect.DeepEqual(got, want) {
		t.Errorf("spec.registries.items.required is %v, want %v — a mirror with no endpoint "+
			"redirects a host to nothing, and every pull for it fails", got, want)
	}

	regProps := crdMap(t, items["properties"], "spec.registries.items.properties")

	for _, f := range []string{"host", "endpoint", "insecureSkipVerify", "overridePath"} {
		if _, ok := regProps[f]; !ok {
			t.Errorf("spec.registries.items.%s is missing from the schema, but main.go reads it", f)
		}
	}

	// The scheme is the plain-HTTP switch, and containerd only complains about a
	// scheme-less endpoint at PULL time — on a node that has already installed
	// and booted. The pattern is what moves that refusal to submission.
	if got := fmt.Sprint(crdMap(t, regProps["endpoint"], "…registries.endpoint")["pattern"]); got != "^https?://" {
		t.Errorf("spec.registries.items.endpoint pattern is %s, want ^https?:// — an endpoint "+
			"with no scheme is accepted here and fails at image pull, hours later", got)
	}
}

func crdDig(t *testing.T, m map[string]interface{}, path ...string) interface{} {
	t.Helper()

	cur := interface{}(m)

	for i, k := range path {
		v, ok := crdMap(t, cur, crdAt(path[:i]))[k]
		if !ok {
			t.Fatalf("%s has no %s", crdPath, crdAt(path[:i+1]))
		}
		cur = v
	}

	return cur
}

func crdAt(path []string) string {
	if len(path) == 0 {
		return "the document"
	}
	return strings.Join(path, ".")
}

func crdMap(t *testing.T, v interface{}, what string) map[string]interface{} {
	t.Helper()

	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("%s is %T, want a mapping", what, v)
	}

	return m
}

func crdList(t *testing.T, v interface{}, what string) []interface{} {
	t.Helper()

	l, ok := v.([]interface{})
	if !ok {
		t.Fatalf("%s is %T, want a list", what, v)
	}

	return l
}

func crdStrings(t *testing.T, v interface{}, what string) []string {
	t.Helper()

	var out []string
	for _, e := range crdList(t, v, what) {
		out = append(out, crdString(t, e))
	}

	return out
}

func crdString(t *testing.T, v interface{}) string {
	t.Helper()

	s, ok := v.(string)
	if !ok {
		t.Fatalf("%v is %T, want a string", v, v)
	}

	return s
}
