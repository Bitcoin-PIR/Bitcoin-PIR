#!/bin/sh

set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH='' cd -- "$script_directory/.." && pwd -P)
dockerfile="$script_directory/fixtures/payment-v1-systemd-255.4-pid1.Dockerfile"
image="bitcoinpir-payment-v1-systemd-255-4-test:local-$$"
container="bitcoinpir-payment-v1-systemd-255-$$"
build_context=$(mktemp -d /tmp/bitcoinpir-payment-v1-systemd-build.XXXXXX)

case "$container" in
  bitcoinpir-payment-v1-systemd-255-[0-9]*) ;;
  *) echo "systemd-255-pid1=FAIL: unsafe disposable container name" >&2; exit 1 ;;
esac
case "$build_context" in
  /tmp/bitcoinpir-payment-v1-systemd-build.*) ;;
  *) echo "systemd-255-pid1=FAIL: unsafe disposable build context" >&2; exit 1 ;;
esac

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
  rm -rf -- "$build_context"
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null
test -f "$dockerfile"
server_arch=$(docker version --format '{{.Server.Arch}}')
case "$server_arch" in
  amd64) platform_arch=amd64 ;;
  arm64|aarch64) platform_arch=arm64 ;;
  *) echo "systemd-255-pid1=FAIL: unsupported Docker server architecture $server_arch" >&2; exit 1 ;;
esac
platform="linux/$platform_arch"
docker build \
  --platform "$platform" \
  --file "$dockerfile" \
  --tag "$image" \
  "$build_context"

docker run --detach \
  --platform "$platform" \
  --name "$container" \
  --privileged \
  --cgroupns=host \
  --tmpfs /run \
  --tmpfs /run/lock \
  --volume /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --volume "$repository:/work:ro" \
  --workdir /work \
  "$image" >/dev/null

attempt=0
while :; do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  case "$state" in
    running) break ;;
    degraded|maintenance|stopping|offline)
      docker exec "$container" systemctl --failed --no-legend >&2 || true
      echo "systemd-255-pid1=FAIL: PID1 entered $state" >&2
      exit 1
      ;;
  esac
  attempt=$((attempt + 1))
  if test "$attempt" -ge 200; then
    docker logs "$container" >&2 || true
    echo "systemd-255-pid1=FAIL: PID1 did not reach running" >&2
    exit 1
  fi
  sleep 0.05
done

test "$(docker exec "$container" sh -c "systemctl --version | sed -n '1p'")" = \
  "systemd 255 (255.4-1ubuntu8.15)"
test "$(docker exec "$container" cat /proc/1/comm)" = "systemd"

docker exec \
  --env BITCOINPIR_DISPOSABLE_SYSTEMD_TEST=1 \
  "$container" \
  /work/scripts/payment-v1-directory-publisher-oneshot-systemd.test.sh
docker exec \
  --env BITCOINPIR_DISPOSABLE_SYSTEMD_TEST=1 \
  "$container" \
  /work/scripts/payment-v1-publisher-netns-failed-recovery-systemd.test.sh
docker exec \
  --env BITCOINPIR_DISPOSABLE_SYSTEMD_TEST=1 \
  "$container" \
  /bin/sh /work/scripts/payment-v1-publisher-firewall-guard-systemd.test.sh

echo "systemd-255-pid1=PASS version=255.4-1ubuntu8.15 oneshot=executed failed-recovery=pre-and-post-ready firewall-guard=pre-in-flight-post"
