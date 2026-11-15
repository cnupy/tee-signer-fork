#!/usr/bin/env bash
# One build lane of a release, and the command an approver runs to rebuild a release on their own machine:
#
#   CHAIN=mainnet IMAGE_VARIANT=prod release/release-build.sh DIST
#
# At the root of a clean checkout of the tagged commit. Steps:
#   1. build the release builder image (release/builder.Dockerfile), no cache,
#   2. fetch the Go modules into build/gomod (network: the Go proxy, go.sum),
#      the pinned nitro-cli source and its image (network: GitHub, crates.io,
#      Debian), the NTS crates (network: crates.io, Cargo.lock),
#   3. scripts/generic-images.sh build with SIGNER_BUILDER_IMAGE set: the
#      runners and parent tools in the builder, offline, then the three
#      images, each built twice,
#   4. check that the GCP and Azure images are of IMAGE_VARIANT
#      (release/image-variant.py),
#   5. copy what a release ships into DIST, with DIST/SHA256SUMS. The names
#      carry the chain, and -test for IMAGE_VARIANT=test.
#
# Host prerequisites. The lane checks them before its first long step and
# names the fix of each one that is missing; it installs nothing.
#   - Docker with the containerd image store and buildx.
#   - qemu-user-static (binfmt_misc entry qemu-aarch64 with the F flag) for
#     the arm64 linuxkit, on an x86_64 host. Docker Desktop has its own.
#   - az with the confcom extension at the version of AZ_CONFCOM_VERSION.
#   - git, python3, jq, file, cc (build-essential), nm and readelf
#     (binutils), and the other arch's nm (binutils-aarch64-linux-gnu on an
#     x86_64 host, binutils-x86-64-linux-gnu on an arm64 one): the NTS step
#     checks its archives with them on the host. scripts/deps.sh installs
#     these.
#   - A Go of any version on PATH (it only reads build info; the build uses
#     the builder's).
#   - unshare and ip (util-linux, iproute2), and unprivileged user
#     namespaces: the Azure policy step runs in "unshare -rn". Ubuntu 24.04
#     turns them off; turn them on with
#     sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
#     (/etc/sysctl.d/ to keep it after a reboot).
set -euo pipefail
umask 022
DIST="${1:?usage: release-build.sh DIST}"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
# shellcheck source=../scripts/common.sh
. "$ROOT/scripts/common.sh"
die() { echo "release-build: $*" >&2; exit 1; }

AZ_CONFCOM_VERSION=2.3.0
IMAGE_VARIANT="${IMAGE_VARIANT:-prod}"
export IMAGE_VARIANT
case "$IMAGE_VARIANT" in prod | test) ;; *) die "IMAGE_VARIANT must be prod or test" ;; esac

# tree_clean ALLOW: no local change, no untracked file, and no ignored file
# or folder besides those that match the regex ALLOW (git status names an
# ignored folder as "!! name/").
tree_clean() {
  local left
  left="$(git status --porcelain --untracked-files=normal --ignored=matching | grep -Ev "^!! ($1)\$" || true)"
  [ -z "$left" ] || die "the tree is not a clean checkout: $(echo "$left" | head -n 5 | tr '\n' ' ')"
}
# A lane starts without build/ (blst, the module cache and other outputs of
# earlier builds) or any other ignored file; logs/ holds only logs. The Go
# module cache in build/gomod is read-only, so a plain rm -rf fails on it.
[ ! -e build ] || die "build/ is left from an earlier build; a lane starts without it. Remove it with: chmod -R u+w build && rm -rf build"
tree_clean 'logs/'
[ -z "${SIGNER_BUILD_OVERLAY_DIR:-}" ] || die "a release never uses the build overlay"

# The host programs and settings the lane uses outside its containers (see
# the header). Every missing one is reported, then the lane stops.
missing=()
# need PROGRAM FIX
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$1 not found: $2"); }
need git "apt-get install git"
need docker "install Docker"
need python3 "apt-get install python3"
need jq "apt-get install jq"
need file "apt-get install file"
need go "install a Go of any version and put it on PATH"
need cc "apt-get install build-essential"
need readelf "apt-get install binutils"
need unshare "apt-get install util-linux"
need ip "apt-get install iproute2"
for a in x86_64 aarch64; do
  t="$(tool_for "$a" nm)"
  if [ "$t" = nm ]; then need nm "apt-get install binutils"; else need "$t" "apt-get install binutils-${a//_/-}-linux-gnu"; fi
done
got="$(az extension show --name confcom --query version -o tsv 2>/dev/null || true)"
[ "$got" = "$AZ_CONFCOM_VERSION" ] || missing+=("az confcom is '$got', want $AZ_CONFCOM_VERSION (az extension add --name confcom --version $AZ_CONFCOM_VERSION)")
if command -v unshare >/dev/null 2>&1 && ! unshare -rn true >/dev/null 2>&1; then
  missing+=("unshare -rn fails: unprivileged user namespaces are off (Ubuntu 24.04: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)")
fi
if command -v docker >/dev/null 2>&1; then
  docker buildx version >/dev/null 2>&1 || missing+=("docker buildx not found: install the buildx plugin (docker-buildx-plugin)")
  if ! ds="$(docker info --format '{{json .DriverStatus}}' 2>/dev/null)"; then
    missing+=("docker info failed: is the Docker daemon running and reachable by this user?")
  else case "$ds" in
    *io.containerd.snapshotter*) ;;
    *) missing+=("docker does not use the containerd image store: set \"features\": {\"containerd-snapshotter\": true} in /etc/docker/daemon.json and restart dockerd (Docker Desktop: Settings, General, Use containerd for pulling and storing images)") ;;
  esac; fi
fi
if [ ${#missing[@]} -gt 0 ]; then
  printf 'release-build: %s\n' "${missing[@]}" >&2
  die "the host lacks ${#missing[@]} prerequisite(s), see the header of release/release-build.sh"
fi

# The time stamp of the licence archives and SBOMs: the commit time of HEAD,
# or SOURCE_DATE_EPOCH when set (the tagged commit's time, when the release
# tooling sits on top of the tag as local commits).
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
commit="$(git rev-parse HEAD)"
start=$(date +%s)

# RELEASE_BUILDER_IMAGE names a builder image of release/builder.Dockerfile
# that is already loaded, one the operator built from this Dockerfile or a
# pinned one. It needs RELEASE_BUILDER_ID, that image's id
# (docker image inspect --format '{{.Id}}'), and the lane refuses an image
# with another id. Unset, the lane builds the builder from the Dockerfile
# without cache, and checks it against RELEASE_BUILDER_ID when that is set.
if [ -n "${RELEASE_BUILDER_IMAGE:-}" ]; then
  [ -n "${RELEASE_BUILDER_ID:-}" ] || die "RELEASE_BUILDER_IMAGE needs RELEASE_BUILDER_ID, the id of that image"
  export SIGNER_BUILDER_IMAGE="$RELEASE_BUILDER_IMAGE"
else
  export SIGNER_BUILDER_IMAGE="signer-release-builder:$commit"
  docker buildx build -q --no-cache --load -f release/builder.Dockerfile -t "$SIGNER_BUILDER_IMAGE" release >/dev/null
fi
builder_id="$(docker image inspect "$SIGNER_BUILDER_IMAGE" --format '{{.Id}}')"
log "builder image $SIGNER_BUILDER_IMAGE ($builder_id)"
[ -z "${RELEASE_BUILDER_ID:-}" ] || [ "$builder_id" = "$RELEASE_BUILDER_ID" ] ||
  die "builder image $SIGNER_BUILDER_IMAGE is $builder_id, not RELEASE_BUILDER_ID $RELEASE_BUILDER_ID"
# Run every later step by id, so a retag of the name during the lane changes nothing.
export SIGNER_BUILDER_IMAGE="$builder_id"

export SIGNER_GOMODCACHE="$BUILD/gomod"
mkdir -p "$SIGNER_GOMODCACHE"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOMODCACHE=/gomod \
  -v "$SIGNER_GOMODCACHE:/gomod" -v "$ROOT:$ROOT" -w "$ROOT" \
  "$SIGNER_BUILDER_IMAGE" bash release/build.sh fetch
bash scripts/nitro-cli-image.sh >/dev/null
bash scripts/fetch-nts.sh
# The fetch steps had network and the tree read-write: they may write only
# into build/ and logs/.
tree_clean 'build/|logs/'
# The arm64 linuxkit of the EIF build runs through qemu-user (binfmt_misc,
# F flag). Check it now rather than after the runner builds; nitro-eif.sh
# checks it again.
if [ "$HOST_ARCH" != aarch64 ]; then
  docker run --rm --pull=never --network none --entrypoint /blobs/linuxkit -v "$NITRO_CLI_DIR/blobs/aarch64:/blobs:ro" \
    "signer-cloud/nitro-cli:$NITRO_CLI_TAG-$HOST_ARCH" version >/dev/null 2>&1 ||
    die "the aarch64 linuxkit does not run on this $HOST_ARCH host: needs qemu-user-static (binfmt_misc entry qemu-aarch64 with the F flag; apt-get install qemu-user-static)"
fi
# The C core for both arches, in the builder: scripts/build-runner.sh also
# links a host-arch runner (the no-platform-tag check) when it builds for
# aarch64 only, and a fresh checkout has no host-arch core yet.
docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT:$ROOT" -w "$ROOT" "$SIGNER_BUILDER_IMAGE" bash scripts/build-core.sh x86_64 aarch64

bash scripts/generic-images.sh build "$BUILD/generic$(image_suffix)"

# The build steps ran with the tree mounted read-write: still the same
# commit, no change to a tracked file, nothing new outside build/ and logs/.
[ "$(git rev-parse HEAD)" = "$commit" ] || die "HEAD moved during the build"
tree_clean 'build/|logs/'

sfx="$(image_suffix)"
az_out="$(bash -c '. "$1/platform-azure/deploy/common.sh" && echo "$OUT"' _ "$ROOT")"
# The GCP image config and the Azure policies must be of IMAGE_VARIANT.
python3 -I release/image-variant.py "$IMAGE_VARIANT" "$BUILD/generic$sfx/fingerprints.txt" \
  "$BUILD/gcp$sfx/runner.oci.tar" "$az_out"/signer-*/policy.rego

# What a release ships, under names that carry the chain, and -test for a
# test lane.
c="$CHAIN"
[ "$IMAGE_VARIANT" = prod ] || c="$CHAIN-$IMAGE_VARIANT"
rm -rf "$DIST"
mkdir -p "$DIST"
# The lane's own values, which release/measurements.py checks its arguments against.
{
  cat "$BUILD/generic$sfx/fingerprints.txt"
  echo "variant $IMAGE_VARIANT"
  echo "commit $commit"
  echo "chain $CHAIN"
} >"$DIST/fingerprints-$c.txt"
for spec in "aarch64:runner-aws$sfx" "x86_64:runner-azure$sfx" "x86_64:runner-gcp$sfx" \
  aarch64:hostagent aarch64:forwarder aarch64:udprelay x86_64:setup-tool aarch64:setup-tool; do
  a="${spec%%:*}" n="${spec#*:}"
  base="$n-$c-linux-$(goarch_of "$a")"
  install -m 0555 "$BUILD/$a/bin/$n" "$DIST/$base"
  tar -C "$BUILD/$a/bin" --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -czf "$DIST/$base.licenses.tar.gz" "$n.licenses"
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOMODCACHE=/gomod \
    -e SOURCE_DATE_EPOCH -v "$SIGNER_GOMODCACHE:/gomod:ro" -v "$ROOT:$ROOT" -v "$DIST:/dist" -w "$ROOT" \
    "$SIGNER_BUILDER_IMAGE" sh -c 'python3 -I release/sbom.py --name "$1" --builder-packages /builder-packages.txt "$2" >"/dist/$1.spdx.json"' \
    _ "$base" "$BUILD/$a/bin/$n"
done
cp "$BUILD/nitro$sfx/runner-aarch64.eif" "$DIST/runner-aws-$c-aarch64.eif"
cp "$BUILD/nitro$sfx/build-enclave-aarch64.json" "$DIST/runner-aws-$c-aarch64.build-enclave.json"
cp "$BUILD/nitro$sfx/inputs-aarch64.txt" "$DIST/runner-aws-$c-aarch64.inputs.txt"
cp "$az_out/runner.oci.tar" "$DIST/runner-azure-$c.oci.tar"
cp "$az_out/runner.inputs" "$DIST/runner-azure-$c.inputs.txt"
cp "$BUILD/gcp$sfx/runner.oci.tar" "$DIST/runner-gcp-$c.oci.tar"
cp "$BUILD/gcp$sfx/runner.inputs" "$DIST/runner-gcp-$c.inputs.txt"
docker run --rm "$SIGNER_BUILDER_IMAGE" cat /builder-packages.txt >"$DIST/builder-packages-$c.txt"
# Into a temporary name first: the redirect of the pipe can create
# SHA256SUMS before the glob runs, which would list the empty file.
(cd "$DIST" && sha256sum -- * | LC_ALL=C sort -k2 >../.SHA256SUMS.$$ && mv ../.SHA256SUMS.$$ SHA256SUMS)
log "release lane done in $(( $(date +%s) - start )) s: $DIST"
