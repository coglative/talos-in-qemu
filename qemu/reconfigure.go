package qemu

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/coglative/talos-in-qemu/cluster"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// reconfigureMachine is the `reconfigure` verb: push an edited manifest to a
// machine that is already running.
//
// IT IS THE ONE VERB THAT NEITHER CREATES NOR DESTROYS. `up` and `adopt` bring
// a machine into being and both SKIP config generation once a talosconfig
// exists — regenerating there would mint a fresh secrets bundle and take away
// the only credential that reaches the node. That skip is correct and it left
// manifest edits with nowhere to go: adding a registry mirror to an adopted node
// meant wiping its disk.
//
// It works for HARDWARE AND GUESTS ALIKE, which is why the substrate only
// decides where to dial. A VM's config is no more regenerable than a node's
// once it holds a secrets bundle, and giving one substrate a door the other
// lacks would be an accident of which one hit the problem first.
func reconfigureMachine(ctx context.Context, d *hvf, path string) error {
	m, err := readMachine(path)
	if err != nil {
		return err
	}

	spec, _ := specBaremetal(m)

	opts := cluster.ReconfigureOptions{
		ClusterName: m.GetName(),
		StateDir:    d.dir(m),
	}

	if isBaremetal(m) {
		if spec == nil {
			return fmt.Errorf("%s has spec.baremetal, but it is not a block of fields", m.GetName())
		}

		network, err := baremetalNetwork(m)
		if err != nil {
			return err
		}

		// THE INSTALLED ADDRESS, never maintenanceEndpoint. A machine that can
		// be reconfigured has left maintenance mode by definition, and dialling
		// the address it answered on during its install is dialling either
		// nothing or, on a re-pinned node, somebody else.
		installedAddr, installed, err := cluster.InstalledEndpoint(baremetalTalosEndpoint(m), network)
		if err != nil {
			return err
		}

		opts.TalosEndpoint = installed
		opts.APIAddress = installedAddr
		opts.KubeEndpoint = baremetalKubeEndpoint(m)
		opts.SystemDisk = cluster.DiskRef{
			Serial: str(spec["systemDiskSerial"], ""),
			WWID:   str(spec["systemDiskWWID"], ""),
		}
		opts.DataDiskSerial = str(spec["dataDiskSerial"], "")
		opts.EphemeralMaxSize = str(spec["ephemeralMaxSize"], "")
		opts.ConsoleArg = str(spec["consoleArg"], "")
		opts.Network = network

		if err := opts.SystemDisk.Validate("install target"); err != nil {
			return err
		}
	} else {
		host, err := d.detect()
		if err != nil {
			return err
		}

		guestSpec, _, _ := unstructured.NestedMap(m.Object, "spec")

		opts.TalosEndpoint = talosEndpoint(m)
		opts.KubeEndpoint = kubeEndpoint(m)
		opts.ConsoleArg = host.ConsoleArg
		// The SAME derivation as upOptions (main.go:550), not a second
		// opinion: kexec is disabled for one host platform, and a guest
		// reconfigured into disagreeing with how it was installed would
		// change its boot path underneath it.
		opts.DisableKexec = host.OS == "darwin" && host.ImageArch == "arm64"
		opts.SystemDisk = cluster.DiskRef{Serial: DiskSerialSystem}
		opts.DataDiskSerial = dataDiskSerial(guestSpec)

		if opts.APIAddress, err = cluster.APIAddressOf(opts.TalosEndpoint); err != nil {
			return err
		}
	}

	mirrors, err := registryMirrors(m)
	if err != nil {
		return err
	}

	opts.Registries = mirrors

	patches, err := configPatches(m)
	if err != nil {
		return err
	}

	opts.ConfigPatches = patches

	log.Printf("regenerating this machine's config from %s and applying it to %s", path, opts.TalosEndpoint)

	if _, err := cluster.Reconfigure(ctx, opts); err != nil {
		// NOT A FAILURE. A manifest that matches the running node is the
		// desired state, and reporting it as an error would make this verb
		// unusable from anything that re-runs it.
		if errors.Is(err, cluster.ErrNothingToApply) {
			log.Printf("nothing to do: this machine is already running the config its manifest describes")

			return nil
		}

		return err
	}

	log.Printf("applied. Talos decides per change whether a reboot is needed, so a mirror lands")
	log.Printf("live and something structural restarts the node; `kubectl get nodes` says which happened")

	return nil
}
