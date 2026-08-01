# Talos in QEMU (TinQ)

Kubernetes nodes as **real VMs running the real production OS**, driven by a
Kubernetes custom resource. No Docker. No root. No nested virtualization.
Linux/KVM and macOS/Hypervisor.framework, on x86_64 and arm64.

```
tinq up examples/bootstrap-machine.yaml
```

Boots a [Talos Linux](https://www.talos.dev) control-plane VM on the host's
native hypervisor via QEMU — KVM on Linux, Hypervisor.framework on macOS — and
drives it all the way to a single-node Kubernetes cluster with a working
StorageClass. Measured on Linux/KVM over two runs: **3.5–4 minutes** cold to a
`Ready` node with storage, of which ~20 seconds is boot to the Talos API.

No `talosctl`, no `kubectl`, no `helm`, no container runtime. `apply` still
exists and still stops at a booted VM in maintenance mode, with the Talos API
forwarded to `127.0.0.1:50000`. Cold boot to "machine is reachable" measured at
~20 seconds on Linux/KVM with a v1.13.7 ISO — and at **~10 seconds** on an M5
Max *before this branch, by hand, and not re-run since*.

Everything below marked *verified* has been run on **both** supported hosts:
Linux/amd64 on KVM, and macOS/arm64 on Hypervisor.framework. The two differ in
one behaviour — kexec, see Status — and where a claim holds on only one of them,
the claim says which.

## Why this exists

`kind` is excellent and it needs a Docker-API container runtime — `docker`,
`podman`, or `nerdctl`. On macOS that means a Linux VM shim (Docker Desktop,
Colima, Rancher, `podman machine`) whose only job is to host the runtime that
hosts the nodes. You maintain a VM to pretend you don't have one.

You also get a node that is a **container sharing one kernel** with every other
node. That is fine until what you are testing is kernel-adjacent — netfilter and
conntrack behavior, sysctls, MTU, offload paths, NAT64, kernel version skew,
CNI datapaths. Then "node" and "shares a kernel with the other nodes" are in
tension, and the thing you were trying to test is the thing the substrate
elides.

TinQ takes the other branch: each node is a VM with its own kernel, running
Talos — an immutable, API-driven Kubernetes OS that many people also run in
production. `minikube`'s hyperkit driver is deprecated; Lima and Colima are
Docker-shaped by design. So on macOS this niche is mostly empty.

**Not a `kind` replacement for everything.** A container node starts faster and
uses less memory, and if you are testing an application on Kubernetes, `kind` is
probably the right tool. TinQ is for when the *node* is part of the test.

## Install

Linux (KVM) or macOS (Hypervisor.framework). TinQ resolves the QEMU binary,
machine type, accelerator and UEFI firmware at runtime from the host it is
running on — nothing is hardcoded to one architecture.

**Linux** — needs QEMU, a working `/dev/kvm`, and your distro's edk2/OVMF
firmware package:

```sh
# Arch
sudo pacman -S qemu-full edk2-ovmf
# Debian/Ubuntu
sudo apt install qemu-system-x86 ovmf
# Fedora
sudo dnf install qemu-system-x86 edk2-ovmf
```

`/dev/kvm` must be readable *and writable by your user*. On distros that gate it
behind a group, add yourself and re-login:

```sh
ls -l /dev/kvm                  # want crw-rw---- root kvm, or crw-rw-rw-
sudo usermod -aG kvm "$USER"    # then log out and back in
```

If `/dev/kvm` is missing or unwritable, TinQ fails loudly rather than silently
falling back to TCG — a Talos VM under emulation is slow enough to look hung.

**macOS** — Hypervisor.framework needs no privileges, only QEMU:

```sh
brew install qemu
```

Then, on either platform:

```sh
go install github.com/coglative/talos-in-qemu/cmd/tinq@latest
```

`up` needs nothing else: the Talos API client and config generator are linked
in, and the storage manifest is embedded. `talosctl` is optional and only needed
for the by-hand sequence below, or for poking at a running node:

```sh
brew install siderolabs/talos/talosctl        # macOS
# Linux: see https://www.talos.dev/latest/talos-guides/install/talosctl/
```

Finally fetch a Talos **ISO matching your host's architecture** and drop it where
TinQ resolves profile names (default `~/.hvf/images`). x86_64 hosts want
`metal-amd64.iso`; arm64 hosts (Apple silicon, arm64 Linux) want
`metal-arm64.iso`:

```sh
mkdir -p ~/.hvf/images
# x86_64 host
curl -Lo ~/.hvf/images/talos-v1.13.7-amd64.iso \
  https://github.com/siderolabs/talos/releases/download/v1.13.7/metal-amd64.iso
# arm64 host
curl -Lo ~/.hvf/images/talos-v1.13.7-arm64.iso \
  https://github.com/siderolabs/talos/releases/download/v1.13.7/metal-arm64.iso
```

The arch has to match the host: TinQ does not emulate a foreign one. Point it at
the wrong ISO and it warns before booting, because the failure mode otherwise
looks like a hang — GRUB comes up (the Talos ISOs ship both `bootx64.efi` and
`bootaa64.efi`), fails to load a kernel it cannot execute, and you get no console
and no API.

**Keep the version in the filename.** `up` reads the Talos version out of the
ISO's volume id and pins `installer:` to it; that pin is not optional (see the
manual sequence below for what it prevents), and the filename is what tells
*you* which release you are on. `up` also refuses outright when the ISO is
newer than the config generator compiled into the binary — Talos config
generation is backwards compatible only, and exceeding it does not fail loudly,
it emits a plausible config for a Talos that does not exist.

## Use

A node is a `TalosMachine`:

```yaml
apiVersion: machine.hvf.fleet.io/v1alpha1
kind: TalosMachine
metadata:
  name: clvc-cp0
spec:
  site: clvc-local          # a path component in the state dir — see "Cleanup"
  role: talos-cp
  # resolved under -image-root when not absolute; on an arm64 host substitute
  # talos-v1.13.7-arm64.iso — the ISO arch must match the host
  image: talos-v1.13.7-amd64.iso
  cpu: 4
  memory: 6Gi
  disk: 20Gi                # the OS disk, serial talos-system
  dataDisk: 40Gi            # OPTIONAL second disk for PVCs, serial talos-data
  hostForwards:
    - { hostPort: 50000, guestPort: 50000 }   # Talos API
    - { hostPort: 6443,  guestPort: 6443 }    # Kubernetes API
```

`dataDisk` is optional; omit it and the VM is byte-for-byte the machine TinQ
built before the field existed. Set it and you get a second
virtio disk with serial `talos-data`, a Talos *user volume* on it, and a
StorageClass provisioning into that volume — one field decides both halves, so
they cannot disagree. **Mind the unit**: `dataDisk: 40` is not a size, decodes
as a number and reads as unset. `up` announces the resulting skip rather than
letting the first sign of it be a `Pending` PVC an hour later.

Both `hostForwards` entries are load-bearing for `up`: 50000 is where it
applies config and bootstraps etcd, and 6443 is written into both the generated
machine config's control-plane endpoint and the kubeconfig, so it has to be an
address *the host* can reach. `up` refuses up front when either is missing
rather than spending a wait's whole budget on an address that was never there.

Three ways to reconcile it:

```sh
# BOOTSTRAP: one machine from a file, no control plane needed
tinq apply   machine.yaml    # a booted VM in maintenance mode, nothing more
tinq up      machine.yaml    # apply, then all the way to a Kubernetes cluster
tinq destroy machine.yaml

# CONTROLLER: watch TalosMachine resources in a cluster
kubectl apply -f crd/talosmachine.yaml
tinq controller --kubeconfig ~/.kube/config
```

`apply` exists because of a chicken-and-egg: a controller needs a control plane
to read resources from, and on a fresh laptop the control plane is the thing you
are trying to create. The usual escape is a `kind` cluster — dragging in a
container runtime purely to bootstrap a hypervisor that doesn't need one. So
`apply` reads one resource from disk and runs it through the **same driver** the
controller loop uses: identical `Observe`/`Create`/`Destroy`, identical QEMU
invocation, identical state layout. Only the source of the resource differs.
Anything else would be two ways to build a machine, and they would drift.

`up` is `apply` plus the cluster, and the VM half is byte-for-byte what
`apply` builds — the same `create()`, the same QEMU invocation, the same state
layout — with the Talos side driven afterwards. A VM already sitting in
maintenance mode is *adopted*, not duplicated, so `apply` then `up` works.
`destroy` keeps working with no hypervisor and no reachable node.

Once the first node is bootstrapped it can host the CRD and TinQ itself, and
every machine after that arrives the normal way.

## One command to a cluster

```sh
tinq up machine.yaml
```

Ten steps, and **the transcript is the feature**. Four of them are not obvious,
and each of those four announces its reason, because each is a failure this
project has actually been bitten by. The intent is that you finish a bring-up
knowing more about Talos than when you started — not that you trust a spinner:

```
[ 1/10] platform      linux/amd64, kvm, qemu-system-x86_64
[ 2/10] image         talos-v1.13.7-amd64.iso -> v1.13.7 (ISO volume id)
[ 3/10] version guard machinery v1.13.7 >= image v1.13.7  ok
[ 4/10] boot          pid 1003824, api 127.0.0.1:50000
[ 5/10] maintenance   reachable after 18s
[ 6/10] config        wrote controlplane.yaml, talosconfig, secrets.yaml
                        diskSelector: serial talos-system
                          a size matcher is a coin flip once there are two large disks, and losing
                          it installs the OS over your PVCs
                        installer: ghcr.io/siderolabs/installer:v1.13.7 (pinned to YOUR image)
                          left unset Talos substitutes THIS binary's version, and a fresh install
                          silently becomes a cross-version upgrade
                        extraKernelArgs: console=ttyS0 (this host's serial)
                          the installed system writes its own cmdline and inherits nothing from the
                          ISO, so serial goes dead at exactly the boot you need to watch
                        userVolume: local-path-provisioner on serial talos-data
                          PVCs get their own disk, so a runaway one cannot wedge etcd on EPHEMERAL
[ 7/10] apply-config  installing... rebooting... api back after 46s
[ 8/10] bootstrap     etcd bootstrapped
                        fired while the node is 'booting', NOT 'running' — waiting for 'running'
                        deadlocks: a control-plane node cannot reach running until etcd exists,
                        and bootstrap is the call that creates etcd
[ 9/10] kubeconfig    wrote kubeconfig, node Ready after 2m40s
I0731 00:10:30.890359 1003799 warnings.go:107] "Warning: would violate PodSecurity \"restricted:latest\": allowPrivilegeEscalation != false (container \"local-path-provisioner\" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container \"local-path-provisioner\" must set securityContext.capabilities.drop=[\"ALL\"]), runAsNonRoot != true (pod or container \"local-path-provisioner\" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container \"local-path-provisioner\" must set securityContext.seccompProfile.type to \"RuntimeDefault\" or \"Localhost\")"
                        ^ client-go relaying the API server's PodSecurity warning. It reads
                          like a failure and is not — see Status. Left in: this is the real,
                          unedited output.
[10/10] storage       local-path-provisioner v0.0.31, default StorageClass
                        root /var/mnt/local-path-provisioner
                          Talos's root filesystem is read-only, so upstream's /opt path cannot work
                        namespace local-path-storage labelled privileged
```

Measured on Linux/KVM (4 vCPU, 6 GiB, v1.13.7) over two runs: **3.5–4 minutes**
cold to a `Ready` node with a bound PVC — the announced waits above sum to
3m44s, and an earlier run of the same machine came in at 3m20s (38s install,
2m24s to `Ready`). Measured earlier on an M5 Max, by hand:
maintenance ~5s, install ~25s, Talos API ~20s after reboot, node registered
~70s, `Ready` ~30s later — roughly 3 minutes.

Four artifacts land in the machine's state directory, at `0600`, so `destroy`
sweeps them with everything else and the secrets do not outlive the cluster:

```sh
export TALOSCONFIG=~/.hvf/<site>/<uid>/talosconfig
export KUBECONFIG=~/.hvf/<site>/<uid>/kubeconfig
kubectl get nodes
```

`up` is **bootstrap only**. It creates a cluster; it never upgrades, scales or
reconciles one. It is also **not resumable** — a failure part way through leaves
a running VM and a state dir, and re-running `up` waits out the maintenance
timeout against a node that has already left maintenance mode. Recovery is
`destroy` and try again, which is what the error tells you.

Three probes that look right and are not, and all three shape the code above: a
TCP connect to a forwarded port succeeds even when nothing listens in the guest
(qemu accepts on the *host*), `talosctl version` always prints the *client's*
tag from a compiled-in constant, and waiting for machine stage `running` before
`bootstrap` is a deadlock rather than a slow path — a control-plane node cannot
reach `running` until etcd exists, and `bootstrap` is what creates etcd.

### Doing it by hand

`up` is not magic and nothing above is hidden from you. This is the same
sequence with `talosctl`, and every flag in it is load-bearing — each one
corresponds to a way it fails:

```sh
tinq apply machine.yaml          # to Talos maintenance mode

cat > patch.yaml <<'YAML'
machine:
  install:
    # SELECT BY SERIAL, never /dev/vdX and never size. Enumeration is decided by
    # qemu arg order, and the read-only boot ISO is also a virtio disk — name a
    # device and you may install onto the install media. Size is no better once
    # spec.dataDisk exists: on the machine in "Use" above, `size: '> 10GB'`
    # matches BOTH the 20Gi system disk and the 40Gi data disk, and losing that
    # coin flip installs the OS over your PVCs. TinQ gives the two disks stable
    # serials for exactly this.
    diskSelector:
      serial: talos-system
    # PIN THE INSTALLER TO THE ISO'S VERSION. Unset, it defaults to talosctl's
    # own version, silently turning a fresh install into a cross-version
    # upgrade. Then nothing fits: a config generated for the newer version is
    # REJECTED by the older maintenance system that has to apply it, and a
    # config for the older one gets installed as the newer, which can hang at
    # /sbin/init with no console output.
    image: ghcr.io/siderolabs/installer:v1.13.7
    # The installed system writes its OWN kernel cmdline and does NOT inherit
    # the ISO's console, so it goes silent on serial at exactly the moment you
    # need to watch it boot.
    # THE CONSOLE NAME IS ARCHITECTURE-SPECIFIC: ttyAMA0 is the arm64 PL011
    # (Apple silicon, arm64 Linux); on x86_64 the serial port is ttyS0. Use the
    # wrong one and you get a booting-but-mute node. No need to guess — `tinq
    # apply` prints the correct value for THIS host right after it creates the
    # VM; copy that line.
    extraKernelArgs:
      - console=ttyAMA0     # arm64;  x86_64: console=ttyS0
YAML

talosctl gen config mycluster https://127.0.0.1:6443 \
  --talos-version v1.13.7 --additional-sans 127.0.0.1 \
  --config-patch @patch.yaml --output-dir . --force

talosctl apply-config --insecure -n 127.0.0.1 -e 127.0.0.1 -f controlplane.yaml
# installs, reboots, and now boots from DISK because of bootindex

export TALOSCONFIG=$PWD/talosconfig
# BOOTSTRAP WHILE THE NODE IS `booting`, NOT `running`. Waiting for running is
# circular: the node cannot reach running until etcd is bootstrapped.
talosctl -n 127.0.0.1 -e 127.0.0.1 bootstrap        # silent on success
talosctl -n 127.0.0.1 -e 127.0.0.1 kubeconfig ./kubeconfig --force

KUBECONFIG=$PWD/kubeconfig kubectl get nodes -w
```

By hand you also get no StorageClass and no user volume: `up`'s step 10 and the
`userVolume` half of step 6 are both things this patch does not do. Use
`talosctl get machinestatus` for liveness — not `talosctl version`.

One more, on x86_64 and true of either path: the `metal-amd64.iso` boots with
`console=tty0` only, so `serial.log` stops after GRUB's `Booting 'Talos ISO'`
even on a perfectly healthy node. Silent serial is not a dead VM — check the
Talos API, not the log. (This is exactly what the `extraKernelArgs` patch fixes
for the *installed* system, which is a different boot.)

And the COUNTER-CASE to that one, because the rule above misfires on it. A console
that stops at

```
[talos] [initramfs] executing /sbin/init
```

with an API that never opens either is the guest waiting for **entropy**. Talos's
`/sbin/init` blocks until the kernel CRNG is seeded, and a QEMU guest with no rng
device has almost nothing to seed it with: no hardware source, no host IRQ jitter
worth counting, and an idle VM generates none of its own. Measured on
darwin/arm64 over five identical boots, `random: crng init done` arrived at 35s,
at 207s, and **never** (>300s) twice — so `[5/10] maintenance` failed **three
times in five** against a five-minute budget, with nothing in the console to say
why. The cure is one device:

```
-device virtio-rng-pci
```

which hands the guest the host's `/dev/urandom`. With it, `crng init done` lands
at `t=0.000000` and maintenance is reachable in **18–20s** every time, against
39s / ~210s / never / never / never without it. Whole bring-ups went from 284s
and 480s (the two that finished at all) to 192–258s across four. TinQ passes the
device, so this is only yours to add if you are driving qemu directly rather than
through `tinq apply`.

So the two mute-console cases are told apart by the API, not by the log: mute
console with a live API is the x86_64 cmdline above; mute console with a dead API,
frozen at `/sbin/init`, is entropy.

And one on **macOS/arm64**, which `up` handles and a hand-rolled config does
not: add

```yaml
machine:
  sysctls:
    kernel.kexec_load_disabled: "1"
```

Talos otherwise kexecs into the kernel it just installed instead of rebooting
through firmware, and under QEMU on macOS that path dies in the guest — the node
installs itself and then never boots what it installed, about six times in ten.
Applied in maintenance mode the sysctl reaches the ISO's running kernel before
the reboot it has to change. Same thing upstream's `talosctl cluster create`
does; see [docs/kexec-on-arm64-macos.md](docs/kexec-on-arm64-macos.md).

### If you plan to run workloads

Talos is not kind, and three defaults differ. `up` decides all three
deliberately, and prints the decision at the end of a bring-up rather than
leaving you to find out:

- **Control-plane taint: REMOVED** (`cluster.allowSchedulingOnControlPlanes:
  true`). Not a security weakening but a topology correction — in production
  there would be worker nodes, and on a single node the taint means nothing can
  ever schedule. A stock Talos control plane is tainted, and a `Deployment` that
  sits `Pending` forever is what that looks like.

- **PodSecurity: STILL ENFORCED** at `baseline` (only `kube-system` exempt),
  which is what a real cluster does and what kind does not. This one is left
  alone on purpose: a workload that needs more is *rejected*, visibly, until you
  say so per namespace —

  ```sh
  kubectl label namespace <ns> pod-security.kubernetes.io/enforce=privileged
  ```

  `up` does this for `local-path-storage` and nothing else, because
  local-path's helper pod uses `hostPath`. Your namespaces stay at `baseline`.

- **Storage: INSTALLED**, when `spec.dataDisk` is set.
  [rancher/local-path-provisioner](https://github.com/rancher/local-path-provisioner)
  v0.0.31 is applied as the **default StorageClass**, so a PVC with no
  `storageClassName` binds instead of hanging `Pending`. Three things about it
  are Talos-specific: the manifest is *embedded and patched*, because upstream
  provisions into `/opt`, which is on Talos's **read-only root filesystem** and
  produces a `Pending` PVC whose reason is buried in an already-collected helper
  pod; PVC data lands on the `talos-data` disk at
  `/var/mnt/local-path-provisioner`, so a runaway PVC cannot wedge etcd by
  filling `EPHEMERAL`; and the binding mode is `WaitForFirstConsumer`, so a PVC
  with no pod stays `Pending` by design until something schedules against it.

  No `spec.dataDisk` means no user volume and no StorageClass. `up` announces
  that skip rather than staying silent about it.

**PVC data does not survive `destroy`.** It lives on `data.qcow2` inside the
machine's state directory, and `destroy` takes the whole state directory. This
is a local development cluster, not a place to keep anything.

## Unprivileged by construction

QEMU **user-mode networking** (SLIRP), so no `vmnet`, no `tap`, no bridge, no
`sudo`. `hostForwards` is how the host reaches the guest.

The tradeoff is real and worth stating: user-mode networking gives each VM NAT'd
egress and forwarded ingress, and **VMs cannot reach each other**. For a single
node, or nodes that only need to be reachable from the host, that is fine. For a
multi-node topology where nodes must be L2-adjacent, QEMU's `socket`, `dgram`
and `hubport` backends provide unprivileged VM-to-VM links — TinQ does not model
them yet (see Status).

## How it works

`driverkit` (174 lines) is the whole controller contract — three verbs:

```go
type Driver interface {
    Observe(ctx, *unstructured.Unstructured) (exists bool, status map[string]any, err error)
    Create (ctx, *unstructured.Unstructured) error
    Destroy(ctx, *unstructured.Unstructured) error
}
```

`Observe` must ask the **external system**, never a local state file. TinQ reads
the pidfile QEMU itself wrote and checks liveness, because a state file happily
reports a long-dead VM as present — that is the bug the signature exists to
prevent.

To support another hypervisor or cloud, implement those three verbs. Everything
else — the finalizer, the reconcile loop, status publication, delete ordering —
is `driverkit`'s.

## Cleanup

`spec.site` is a **path component** in the state directory:

```
~/.hvf/<site>/<uid>/{system.qcow2,efivars.fd,qemu.pid,serial.log}
                    {data.qcow2}                                  # spec.dataDisk
                    {controlplane.yaml,talosconfig,secrets.yaml,kubeconfig}   # -up
```

The four `up` artifacts are written **into the machine's directory**, never one
level up, and at `0600`. That is what makes `destroy` sweep them: a cluster's
private keys must not outlive the cluster, and anything written beside the state
root would be residue the site-tag check cannot find.

`~/.hvf/images/` is **not** state and is never swept — it is where profile names
resolve, and the ISOs there are shared by every machine.

Artifacts carry the identity they belong to, so they can be found and swept
without a registry to consult — the same property that makes cloud labels and
tags work. `Destroy` takes the whole unit: the process and the state directory,
idempotently.

## Status

Working and exercised:

- `apply` / `destroy`, including re-apply (`Observe` reports present, so it
  will not start a second QEMU against the same state directory)
- Talos boots on KVM (Linux/amd64, `q35` + `-cpu host` + distro OVMF); Talos
  API via `hostForwards`
- Talos boots on HVF (macOS/arm64) — *before this branch, by hand, on an M5
  Max*; cold boot to reachable ~10s. Not re-run since; see the macOS bullet
  below
- Controller mode against a cluster with the CRD installed
- `Destroy` sweeps process + state directory

- **A real cluster, end to end** — *before this branch, by hand, on
  macOS/arm64*. Single-node control plane, Kubernetes v1.36.1 on Talos v1.9.5,
  kernel 6.12.18-talos arm64, containerd 2.0.3, node `Ready`, with Crossplane
  and a real workload serving HTTP on it. ~3 minutes cold. This predates `up`
  and predates the platform abstraction; it is history, not a branch result.

- **`up`, end to end, on macOS/arm64.** Nine bring-ups on an Apple-silicon Mac
  (macOS 26.6, QEMU 11.0.2, HVF) with a v1.13.7 arm64 ISO, `cpu: 4` and
  `dataDisk: 40Gi`: node `Ready`, Kubernetes v1.36.2 on Talos v1.13.7, kernel
  6.18.39-talos arm64, containerd 2.2.6, `local-path` the default StorageClass,
  all pods `Running`, `destroy` leaving only `images` and no `qemu-system`
  process. **Two guest-side facts were checked rather than inferred**, because
  the transcript cannot show either: `kernel.kexec_load_disabled` reads `1` from
  `/proc/sys` inside the *installed* system, and `kexec_core: Starting new
  kernel` appears **zero** times against two `Linux version` banners — the
  firmware-reboot signature, at the `cpu: 4` that used to wedge six times in ten.
  The last four runs are 4/4 at 192–258s; the five before them include the three
  entropy failures described under "Doing it by hand", which is what
  `virtio-rng-pci` fixed. Reliability beyond 4/4 is not claimed.

- **`up`, end to end, on Linux/KVM.** Verified on real hardware with a
  v1.13.7 amd64 ISO and `dataDisk: 40Gi`: node `talos-jzb-cu0` `Ready`,
  Kubernetes v1.36.2 on Talos v1.13.7, kernel 6.18.39-talos, containerd 2.2.6,
  no taints; `local-path` the default StorageClass; a `ReadWriteOnce` PVC with
  no `storageClassName` **bound**; an nginx `Deployment` **Available**; a pod
  mounting that PVC wrote a file to it and read it back, from
  `/dev/vdc1 … xfs … /data`. Talos confirms the OS installed to the disk with
  serial `talos-system` and the user volume `u-local-path-provisioner` on
  `talos-data`. `destroy` left `~/.hvf/` holding only `images`, no
  `qemu-system` process and both ports free. 3.5–4 minutes cold over two runs.
  The second run is the transcript shown above, verbatim; it also bound a PVC
  through the pinned `busybox:1.38.0` helper pod, which wrote and read a file
  on it.

Not done yet — stated plainly rather than implied:

- **`up` is bootstrap only, and not resumable.** It creates a cluster; it
  never upgrades, scales or reconciles one, and a failure part way through is
  recovered with `destroy` and a retry rather than by re-running `up`.
- **One stderr line still interleaves with the transcript.** client-go relays
  the API server's `restricted:latest` PodSecurity *warning* during step 10,
  which reads like a failure and is not — the namespace is labelled
  `privileged` and the object is admitted. **The transcript above is a real,
  unedited `up` run**: that line is shown where it actually appears, with a
  two-line annotation under it and nothing removed. (The `extraKernelArgs` hint
  used to interleave too; it now belongs to `apply`, which is the only caller
  that needs it, so it no longer prints during a bring-up.) Suppressing the
  client-go warning means installing a custom `WarningHandler`, which would
  also swallow warnings worth seeing; left visible for now.
- **TCP-only host forwards.** `hostForwards` emits `hostfwd=tcp:` only, so a
  UDP service (QUIC, WebTransport, DNS) has no path from the host. Multi-protocol
  forwards are a small change and not yet made.
- **The "newer ISOs may not boot" warning was macOS-specific, and is now
  narrowed.** The old note here reported v1.13.4 hanging at `executing
  /sbin/init` at 199% CPU with no console and no API; that was observed on
  **macOS/HVF/aarch64**, and it is not a general property of newer Talos.
  **v1.13.7 amd64 is verified to boot and to bring up a full cluster on
  Linux/KVM.** Whether the aarch64/HVF hang persists on current releases is
  untested — see the macOS bullet.
- **No multi-node topology.** One NIC on user-mode networking; no VM-to-VM
  links, so no multi-node cluster and no simulated switch fabric. The QEMU
  backends needed (`socket`/`hubport`) are unprivileged, so this is a modeling
  gap in the resource, not a platform limit.
- **The two hosts differ in one behaviour, and it is guest-side.** Talos reboots
  through kexec after installing; under QEMU on macOS/arm64 that path dies in
  the guest, so `up` sets `kernel.kexec_load_disabled` there and only there.
  Linux/KVM reboots through kexec normally. Both are verified end to end —
  see Status — but a hand-rolled machine config on macOS/arm64 that omits the
  sysctl will wedge roughly six times in ten; see
  [docs/kexec-on-arm64-macos.md](docs/kexec-on-arm64-macos.md).
- **PVC data is disposable.** It lives on `data.qcow2` in the machine's state
  directory and `destroy` takes the whole directory. There is no snapshot, no
  export and no backup.
- **Partial test coverage.** The `platform` package has unit tests — arch
  mapping, accelerator selection, firmware-registry scanning and image-arch
  detection from the kernel's PE header, verified by mutation rather than by
  assertion alone — plus integration tests against the real firmware registry
  and real Talos ISOs when present. The `cluster` package's config generation,
  manifest patching and transcript are unit-tested without a VM; its waits, the
  reboot-mode apply and the kubeconfig retry are only ever proven by a real
  bring-up. The QEMU invocation itself is still verified by running it, which is
  not the same thing.

### Dependencies

TinQ links `siderolabs/talos/pkg/machinery` for the Talos API and config
generator, and `k8s.io/client-go` for the Kubernetes side — no `talosctl`,
`kubectl`, `helm` or `kustomize` on `PATH`, and no container runtime. That is a
real footprint and worth stating rather than burying: 7 direct requires, 79
indirect, 154 modules in the build list. The local-path-provisioner manifest is
vendored into `cluster/` and applied through client-go, so a bring-up makes no
network call of its own beyond what the guest pulls.

## License

MIT — see [LICENSE](LICENSE).
