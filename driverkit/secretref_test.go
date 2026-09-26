package driverkit

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// secretsDynamic serves machines from ri and Secrets from a map keyed "namespace/name".
type secretsDynamic struct {
	ri      *fakeResource
	secrets map[string]map[string]string
}

func (f *secretsDynamic) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	if gvr.Resource == "secrets" {
		return &secretNS{secrets: f.secrets}
	}
	return f.ri
}

type secretNS struct {
	dynamic.NamespaceableResourceInterface // anything else panics
	secrets                                map[string]map[string]string
	ns                                     string
}

func (s *secretNS) Namespace(ns string) dynamic.ResourceInterface {
	return &secretNS{secrets: s.secrets, ns: ns}
}

func (s *secretNS) Get(_ context.Context, name string, _ metav1.GetOptions, _ ...string) (*unstructured.Unstructured, error) {
	data, ok := s.secrets[s.ns+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	}
	enc := map[string]interface{}{}
	for k, v := range data {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{"data": enc}}, nil
}

// ctxDriver records what the reconcile handed Observe.
type ctxDriver struct {
	fakeDriver
	saw map[string][]byte
}

func (d *ctxDriver) Observe(ctx context.Context, m *unstructured.Unstructured) (State, map[string]interface{}, error) {
	d.saw, _ = SecretFrom(ctx)
	return d.fakeDriver.Observe(ctx, m)
}

func withSecretRef(m *unstructured.Unstructured) *unstructured.Unstructured {
	_ = unstructured.SetNestedStringMap(m.Object, map[string]string{"namespace": "ws", "name": "site-ffd-talos"}, "spec", "secretRef")
	return m
}

func TestAMachineWhoseSecretIsMissingIsNotTouched(t *testing.T) {
	sentinel := errors.New("observed")
	d := &fakeDriver{state: Absent, observeErr: sentinel}
	err := reconcile(context.Background(), &secretsDynamic{ri: &fakeResource{}}, Config{Finalizer: testFinalizer}, d, withSecretRef(managed("Running")))
	if err == nil || errors.Is(err, sentinel) || !strings.Contains(err.Error(), "spec.secretRef ws/site-ffd-talos") {
		t.Fatalf("got %v; want a refusal naming the Secret, before the driver is asked anything", err)
	}
	if d.created != 0 {
		t.Fatal("created a machine without its Secret")
	}
}

func TestTheDriverReceivesTheReferencedSecret(t *testing.T) {
	d := &ctxDriver{fakeDriver: fakeDriver{state: Running}}
	dc := &secretsDynamic{ri: &fakeResource{}, secrets: map[string]map[string]string{
		"ws/site-ffd-talos": {"bundle.yaml": "b", "patches.yaml": "p"}}}
	if err := reconcile(context.Background(), dc, Config{Finalizer: testFinalizer}, d, withSecretRef(managed("Running"))); err != nil {
		t.Fatal(err)
	}
	if string(d.saw["bundle.yaml"]) != "b" || string(d.saw["patches.yaml"]) != "p" {
		t.Fatalf("driver saw %v", d.saw)
	}
}
