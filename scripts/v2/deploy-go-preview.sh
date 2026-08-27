#!/bin/sh
set -eu

# Deploys the current Go/Svelte source tree to the :10443 owner-preview
# container -- the ONLY correct way to redeploy it. Never hand-run
# `rm -rf frontend-dist && cp -r dist frontend-dist`: that wipes every
# previously-served content-hashed asset file, which breaks any
# already-open browser tab whose in-memory bundle still references the
# old filenames (a real defect found live, see PARITY_MATRIX.md's
# "Frontend deployment integrity" row and internal/httpapi/static.go's
# own doc comment).
#
# Two real guarantees this script provides:
#   1. Old content-hashed asset files under assets/ are NEVER deleted
#      on deploy (only ever added to) -- an already-open browser tab
#      can always still fetch whatever chunk filenames it already
#      knows about, indefinitely.
#   2. index.html (the one file that must always point at the CURRENT
#      build's own filenames) is swapped in with a single rename(2),
#      so no request is ever served a half-written index.html.
#
# Usage: scripts/v2/deploy-go-preview.sh

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GO_DIR="$REPO_ROOT/go"
RELEASE=/root/apdns-go-migration-preview-release
HOSTAGENT_DIR=/root/apdns-go-migration-hostagent
CONTAINER=apdns-go-migration-preview
WEB_UID=996
WEB_GID=986

fail() { echo "DEPLOY FAILED: $*" >&2; exit 1; }

cd "$REPO_ROOT"
SHA="$(git rev-parse --short=12 HEAD)"
VERSION="2.0.0~go-${SHA}"
echo "+ deploying commit $SHA as version $VERSION"

echo "+ building frontend"
(cd "$GO_DIR/frontend" && npm run build >/dev/null)

echo "+ building binaries"
(cd "$GO_DIR" && go build -buildvcs=false -ldflags "-X main.Version=${VERSION}" -o /tmp/deploy-go-preview-web ./cmd/alderpointdns-go)
(cd "$GO_DIR" && go build -buildvcs=false -o /tmp/deploy-go-preview-hostagent ./cmd/apdns-hostagent)
/tmp/deploy-go-preview-web version | grep -qx "$VERSION" || fail "built binary does not self-report the expected version"

echo "+ merge-deploying frontend assets (never deletes old chunks)"
mkdir -p "$RELEASE/frontend-dist/assets"
cp -n "$GO_DIR/frontend/dist/assets/"* "$RELEASE/frontend-dist/assets/" 2>/dev/null || true
chown -R "$WEB_UID:$WEB_GID" "$RELEASE/frontend-dist/assets"

echo "+ syncing schema/migrations (the binary reads these from disk at startup --"
echo "  a migration added in this commit is inert until this copy happens)"
mkdir -p "$RELEASE/schema/migrations"
cp "$GO_DIR/schema/migrations/"*.sql "$RELEASE/schema/migrations/"
chown -R root:root "$RELEASE/schema"

echo "+ atomically swapping index.html"
cp "$GO_DIR/frontend/dist/index.html" "$RELEASE/frontend-dist/index.html.new"
chown "$WEB_UID:$WEB_GID" "$RELEASE/frontend-dist/index.html.new"
mv "$RELEASE/frontend-dist/index.html.new" "$RELEASE/frontend-dist/index.html"

echo "+ atomically swapping the web binary"
cp /tmp/deploy-go-preview-web "$RELEASE/alderpointdns-go.new"
chmod 755 "$RELEASE/alderpointdns-go.new"
mv "$RELEASE/alderpointdns-go.new" "$RELEASE/alderpointdns-go"

echo "+ atomically swapping apdns-hostagent"
cp /tmp/deploy-go-preview-hostagent "$HOSTAGENT_DIR/apdns-hostagent.new"
chmod 700 "$HOSTAGENT_DIR/apdns-hostagent.new"
mv "$HOSTAGENT_DIR/apdns-hostagent.new" "$HOSTAGENT_DIR/apdns-hostagent"

rm -f /tmp/deploy-go-preview-web /tmp/deploy-go-preview-hostagent

echo "+ restarting apdns-hostagent (real host-level BIND/dnsdist processes it was supervising"
echo "  are orphaned by this, not killed -- DNS keeps answering through the restart; a fresh"
echo "  dns_runtime.promote call after this script finishes re-adopts them under the new process)"
pkill -f "$HOSTAGENT_DIR/apdns-hostagent" 2>/dev/null || true
sleep 1
# shellcheck disable=SC2086
nohup setsid "$HOSTAGENT_DIR/apdns-hostagent" \
  -socket /root/apdns-go-migration-preview-state/hostagent-socket/agent.sock \
  -allowed-uid "$WEB_UID" \
  -audit-log "$HOSTAGENT_DIR/audit/audit.jsonl" \
  -log-unit-map "apdns-go-web=$CONTAINER,apdns-hostagent=$HOSTAGENT_DIR/hostagent.log" \
  -log-container-units apdns-go-web \
  -log-file-units apdns-hostagent \
  -rndc-conf /root/apdns-v2-preview-state/etc/rndc.conf \
  -bind-compiled-dir /root/apdns-v2-preview-state/var-lib/compiled/bind \
  -control-db /root/apdns-v2-preview-state/var-lib/control.db \
  -current-binary "$RELEASE/alderpointdns-go" \
  -update-staging-dir "$HOSTAGENT_DIR/update-staging" \
  -update-backup "$HOSTAGENT_DIR/previous-binary" \
  -web-health-url https://127.0.0.1:10443/api/health \
  -dns-runtime-staging-dir "$HOSTAGENT_DIR/dns-staging" \
  -dns-runtime-bind-conf /var/lib/bind/apdns-go-migration-preview/named.conf \
  -dns-runtime-dnsdist-conf "$HOSTAGENT_DIR/dns-staging/dnsdist.conf" \
  -dns-runtime-bind-dir /var/lib/bind/apdns-go-migration-preview \
  -dns-runtime-bind-plain-port 25453 -dns-runtime-bind-proxy-port 25553 \
  -dns-runtime-bind-stats-port 28153 -dns-runtime-bind-rndc-port 29553 \
  -dns-runtime-dnsdist-listen-addr 127.0.0.1:25333 \
  > "$HOSTAGENT_DIR/hostagent.log" 2>&1 < /dev/null &

echo "+ recreating the preview container (podman restart does NOT pick up a"
echo "  changed command line -- e.g. a flag this deploy's own binary no longer"
echo "  accepts -- only a real rm+run does; this bit a real deploy once already)"
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
podman run -d --name "$CONTAINER" \
  --user "$WEB_UID:$WEB_GID" \
  --group-add 103 \
  -p 10443:10443 \
  -v /root/apdns-v2-preview-state/var-lib/analytics:/var/lib/alderpointdns-v2-analytics-ro:ro \
  -v /root/apdns-v2-preview-state/var-lib/certs:/var/lib/alderpointdns-v2-certs-ro:ro \
  -v "$RELEASE:/opt/alderpointdns-go:ro" \
  -v /root/apdns-go-migration-preview-state/etc:/etc/alderpointdns-go \
  -v /root/apdns-go-migration-preview-state/var-lib:/var/lib/alderpointdns-go \
  -v /root/apdns-go-migration-preview-state/hostagent-socket:/run/apdns-hostagent \
  debian:trixie-slim \
  /opt/alderpointdns-go/alderpointdns-go web \
    -db /var/lib/alderpointdns-go/data/app.db \
    -config /etc/alderpointdns-go/appliance.yaml \
    -static /opt/alderpointdns-go/frontend-dist \
    -migrations /opt/alderpointdns-go/schema/migrations \
    -analytics-db /var/lib/alderpointdns-v2-analytics-ro/aggregates.db \
    -query-log-dir /var/lib/alderpointdns-v2-analytics-ro/queries \
    -backups-dir /var/lib/alderpointdns-go/backups \
    -hostagent-socket /run/apdns-hostagent/agent.sock \
    -dns-runtime-dnsdist-addr 127.0.0.1:25333 \
    -dns-runtime-bind-proxy-addr 127.0.0.1:25553 \
    -addr 0.0.0.0:10443 >/dev/null

sleep 2
HEALTH="$(curl -sk https://127.0.0.1:10443/api/health)"
echo "+ health: $HEALTH"
echo "$HEALTH" | grep -q "\"version\":\"$VERSION\"" || fail "deployed version does not match expected $VERSION"

echo "+ done. Remember: a dns_runtime.promote (via the DNS Runtime page's Apply button, or the"
echo "  next resolver-affecting save) is needed to bring BIND/dnsdist under the new hostagent's"
echo "  own supervision if they were already running before this restart."
