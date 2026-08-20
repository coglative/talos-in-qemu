# tinq as a container, so a branch SUT can be an ordinary Kubernetes pod.
#
# WHY THIS EXISTS. tinq ships a binary and assumes a host: `tinq up` runs qemu where you invoked it.
# That is right for a laptop and leaves no way to run a Talos guest as a workload — so a consumer
# needing one (branchspace, for a per-branch test cluster) reimplemented qemu invocation in a shell
# script and rediscovered four things tinq already knew: bootindex over `-boot d`, disk-by-serial
# over `/dev/vda`, `console=ttyS0` per arch, and hostfwd needing an explicit address.
#
# The duplication was not carelessness. There was no artifact to depend on, so the knowledge got
# re-derived at the call site, worse. An image is what makes tinq depend-on-able from Kubernetes.
#
# UNPRIVILEGED BY CONSTRUCTION, except for /dev/kvm. The image needs no capabilities of its own; the
# pod that runs it needs a /dev/kvm device, which is either a hostPath in a privileged namespace or
# a device plugin. That is a property of the POD, deliberately not baked in here.
FROM alpine:3.20 AS build
RUN apk add --no-cache go git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off and a static link: the runtime stage has no toolchain, and a dynamically linked binary
# would fail at exec with a message about a missing loader rather than about anything real.
RUN CGO_ENABLED=0 go build -trimpath -o /out/tinq ./cmd/tinq

FROM alpine:3.20
# qemu-system-x86_64 is the actuator; the rest are what a Talos bring-up genuinely needs.
#   xorriso  -- extract kernel+initrd from the ISO, so the guest console can be put on ttyS0
#   socat    -- bridge an IPv4-only slirp forward to an IPv6-only pod network
#   curl     -- fetch the boot image
# socat is here because of a finding tinq does not yet have: QEMU user-mode networking has no IPv6
# hostfwd, so on an IPv6-only cluster the guest's forwarded ports land on an address family the pod
# does not have. Shipping the tool does not fix that; it makes the fix expressible.
RUN apk add --no-cache qemu-system-x86_64 qemu-img xorriso socat curl ca-certificates
COPY --from=build /out/tinq /usr/local/bin/tinq
# NO ENTRYPOINT ARGUMENTS. What a venue does -- up, adopt, reconfigure -- is the caller's decision,
# and defaulting it here would make a pod's behaviour depend on an image tag rather than on its spec.
ENTRYPOINT ["/usr/local/bin/tinq"]
