#!/bin/sh
set -eu

# Deploys the current V2 source tree to the persistent, isolated
# build-server owner-preview container (see docs/v2/owner-preview.md).
#
# This is a DEVELOPMENT deployment, not a release: it builds a .deb whose
# version string encodes the exact deployed Git SHA
# (2.0.0~preview<shortsha>-1) via scripts/build-v2-deb.sh, installs it
# into the already-running "apdns-v2-preview" podman container with
# `apt-get install` (a real upgrade-in-place, exercising the same
# postinst path every real install/upgrade goes through), and leaves
# /etc/alderpointdns-v2 and /var/lib/alderpointdns-v2 untouched (they are
# host bind-mounts, not part of the container's own ephemeral layer --
# see setup notes in docs/v2/owner-preview.md). It never bumps the
# private RC version, never touches the V1 install on this host, and
# never pushes/tags/releases anything.
#
# Usage:
#   scripts/dev/deploy-v2-preview.sh            # deploy current HEAD
#   scripts/dev/deploy-v2-preview.sh --reset     # wipe preview state first (fresh first-run), then deploy
#   scripts/dev/deploy-v2-preview.sh --smoke-only  # skip build/install, just re-run the smoke check

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTAINER=apdns-v2-preview
STATE_ETC=/root/apdns-v2-preview-state/etc
STATE_VARLIB=/root/apdns-v2-preview-state/var-lib
# Normal V2 appliance listener ports. V1.1.1 was removed from active
# service on this build server specifically so V2's preview could own
# these (see docs/v2/owner-preview.md) -- the old development-only
# 18443/18053 mappings are no longer used as the primary interface.
MGMT_PORT=8443
DNS_PORT=53

fail() { echo "DEPLOY FAILED: $*" >&2; exit 1; }

RESET=0
SMOKE_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --reset) RESET=1 ;;
    --smoke-only) SMOKE_ONLY=1 ;;
    *) fail "unknown argument: $arg" ;;
  esac
done

podman inspect "$CONTAINER" >/dev/null 2>&1 || fail "preview container '$CONTAINER' does not exist -- see docs/v2/owner-preview.md to (re)create it"

if [ "$RESET" = 1 ]; then
  echo "+ RESET requested: this destroys all preview config/state (admin account, clients, blocklists, everything) for a fresh first-run experience."
  read -r -p "  Type 'reset' to confirm: " confirm
  [ "$confirm" = "reset" ] || fail "reset not confirmed"
  podman stop "$CONTAINER" >/dev/null
  rm -rf "${STATE_ETC:?}"/* "${STATE_VARLIB:?}"/*
  podman start "$CONTAINER" >/dev/null
  echo "+ preview state wiped; container restarted"
fi

if [ "$SMOKE_ONLY" = 0 ]; then
  cd "$REPO_ROOT"
  [ -z "$(git status --porcelain)" ] || fail "worktree is not clean -- deploy only from a clean coherent source state (git status --porcelain is non-empty)"
  SHA="$(git rev-parse --short=10 HEAD)"
  VERSION="2.0.0~preview${SHA}-1"
  echo "+ building $VERSION from HEAD $SHA"
  WORK="$(mktemp -d /tmp/apdns-v2-preview-build.XXXXXX)"
  DEB="$(./scripts/build-v2-deb.sh --output-dir "$WORK" --version "$VERSION")" || fail "build-v2-deb.sh failed"
  [ -f "$DEB" ] || fail "build-v2-deb.sh did not produce a .deb"

  echo "+ deploying $VERSION to $CONTAINER"
  podman cp "$DEB" "$CONTAINER:/tmp/alderpointdns-v2.deb" || fail "podman cp failed"
  # Real defect fixed here (hit live, this pass): the preview version
  # string is 2.0.0~preview<shortsha>-1 -- a real git short SHA, which
  # is NOT monotonically ordered hex (unlike an RC/build number). Two
  # consecutive real commits can legitimately produce a "lower" dpkg
  # version by Debian's comparison rules than the one currently
  # installed (observed live: preview9cd5cdb228 sorted below
  # previewe8f5f04475), which apt correctly refuses as a "downgrade"
  # without --allow-downgrades. This is expected and safe for a dev-only
  # preview loop (always installing the current, coherent HEAD -- never
  # an intentionally-older one, and never a real RC/release line, which
  # never uses this version scheme) -- an RC install must NEVER pass
  # this flag, only this development preview path.
  podman exec "$CONTAINER" sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq --allow-downgrades /tmp/alderpointdns-v2.deb' \
    || { podman exec "$CONTAINER" journalctl -u alderpointdns-v2-web -n 60 --no-pager 2>&1 || true; fail "apt-get install failed inside the preview container -- see journalctl output above"; }
  rm -rf "$WORK"
fi

echo "+ smoke check"
for i in $(seq 1 30); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${MGMT_PORT}/api/setup/status" || echo 000)"
  [ "$code" = "200" ] && break
  sleep 1
done
[ "$code" = "200" ] || fail "management UI did not answer 200 on /api/setup/status (got $code) after deploy"

for svc in alderpointdns-v2-web alderpointdns-v2-dnsdist "alderpointdns-v2-bind@ctx0"; do
  state="$(podman exec "$CONTAINER" systemctl is-active "$svc" 2>/dev/null || echo unknown)"
  [ "$state" = "active" ] || fail "$svc is not active after deploy (state: $state)"
done

dns_answer="$(dig @127.0.0.1 -p "$DNS_PORT" example.com +short +time=3 2>/dev/null || true)"
[ -n "$dns_answer" ] || fail "real DNS query via the preview's dnsdist (port $DNS_PORT) returned no answer"

installed_version="$(podman exec "$CONTAINER" cat /opt/alderpointdns-v2/VERSION 2>/dev/null || echo unknown)"
echo
echo "DEPLOY OK"
echo "  Deployed version : $installed_version"
echo "  Management UI    : https://172.16.43.100:${MGMT_PORT}/  (self-signed cert; also reachable at https://127.0.0.1:${MGMT_PORT}/ from this host)"
if [ "$DNS_PORT" = "53" ]; then
  echo "  DNS for testing  : 172.16.43.100, standard port 53 (both UDP and TCP) -- e.g. dig @172.16.43.100 example.com"
else
  echo "  DNS for testing  : 172.16.43.100 port ${DNS_PORT} (both UDP and TCP) -- NOT port 53; e.g. dig @172.16.43.100 -p ${DNS_PORT} example.com"
fi
echo "  State            : preserved (bind-mounted at $STATE_ETC and $STATE_VARLIB) unless --reset was passed"
