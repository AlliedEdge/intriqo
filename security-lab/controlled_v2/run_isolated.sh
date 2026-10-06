#!/usr/bin/env bash
# Run the controlled-v2 controller in a private Docker network namespace.
# The image is expected to be available locally; no package or dataset network
# access is used.  Host iproute2/Python binaries are bind-mounted read-only so
# this remains reproducible with the repository's existing local image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RAW_ROOT="${INTRIQO_V2_RAW_ROOT:-/tmp/opencode/intriqo-controlled-v2/raw}"
SCENARIO_ID="${1:?usage: run_isolated.sh SCENARIO_ID}"

mkdir -p "$RAW_ROOT"

# Docker's default proc mount is read-only; privileged is required only so the
# child namespaces can set their own forwarding/IPv6 sysctls and mount
# /run/netns.  The container still has no network device or route outside its
# private namespace and is removed after the episode.
exec docker run --rm \
  --name intriqo-controlled-v2-controller \
  --network none \
  --privileged \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --tmpfs /run:rw,noexec,nosuid,nodev \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add SYS_ADMIN \
  --cap-add DAC_OVERRIDE \
  --pids-limit 128 \
  -e TZ=UTC \
  -e INTRIQO_V2_HOST_RAW_ROOT="$RAW_ROOT" \
  -v "$REPO_ROOT:/workspace:rw" \
  -v "$RAW_ROOT:/raw:rw" \
  -v /usr/bin/python3:/usr/bin/python3:ro \
  -v /usr/bin/ip:/usr/bin/ip:ro \
  -v /usr/sbin/tc:/usr/sbin/tc:ro \
  -v /usr/sbin/bridge:/usr/sbin/bridge:ro \
  -v /usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:ro \
  -v /lib64/ld-linux-x86-64.so.2:/lib64/ld-linux-x86-64.so.2:ro \
  -v /usr/lib/python3:/usr/lib/python3:ro \
  -v /usr/lib/python3.14:/usr/lib/python3.14:ro \
  ubuntu:26.04 \
  python3 /workspace/security-lab/controlled_v2/controller.py \
    --scenario-id "$SCENARIO_ID" \
    --raw-root /raw
