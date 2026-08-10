#!/bin/sh
set -eu

# Regression test for a real beta.6 -> 1.0.0 upgrade failure found on a
# disposable Debian appliance: alderpointdns.service failed to start
# (status=226/NAMESPACE, "Failed to set up mount namespacing: /etc/netplan:
# No such file or directory") because packaging/alderpointdns.service's
# ReadWritePaths= listed /etc/netplan, /etc/systemd/network, and
# /etc/network unconditionally. Only one of those three networking-backend
# directories is ever actually in use on a given host (app/network_config.py
# detect_backend() picks exactly one), and a real Debian install is not
# guaranteed to have all three backends' packages present -- /etc/netplan
# in particular is Ubuntu-centric. Unlike ReadOnlyPaths=, a plain
# ReadWritePaths= entry for a path that does not exist is FATAL to the
# whole unit's mount-namespace setup, not silently skipped; a leading "-"
# (systemd.exec(5)) is required to make an entry optional.
#
# This host (the same appliance environment the acceptance suite runs
# against) genuinely lacks /etc/netplan, exactly like the appliance where
# the bug was found -- so the checks below exercise the real fix on the
# real missing directory, not a synthetic simulation.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

command -v systemd-run >/dev/null 2>&1 || fail "systemd-run is required"

UNIT="$(mktemp -u alderpointdns-optpaths-test-XXXXXX)"
RW_LINE="$(grep '^ReadWritePaths=' /opt/alderpointdns/packaging/alderpointdns.service)"
RW_VALUE="${RW_LINE#ReadWritePaths=}"

# -- sanity: this environment actually reproduces the reported bug's
#    precondition, or this whole test would be vacuous --
[ -e /etc/netplan ] && fail "test environment has /etc/netplan -- this test needs a host without it to be meaningful (see docs/testing.md for a substitute host)"

# -- exactly the three backend-selection paths are optional; nothing else
#    in the list had its hardening weakened --
for optional in /etc/netplan /etc/systemd/network /etc/network; do
  case " $RW_VALUE " in
    *" -$optional "*) : ;;
    *) fail "packaging/alderpointdns.service's ReadWritePaths= does not mark $optional optional (\"-$optional\")" ;;
  esac
done
for guaranteed in /var/lib/alderpointdns /var/log/alderpointdns /etc/alderpointdns /etc/bind /etc/dnsdist /etc/systemd/system /etc/sudoers.d; do
  case " $RW_VALUE " in
    *" -$guaranteed "*) fail "packaging/alderpointdns.service marks the guaranteed path $guaranteed optional -- writable-path hardening must not be broadly weakened" ;;
    *" $guaranteed "*) : ;;
    *) fail "packaging/alderpointdns.service's ReadWritePaths= is missing the guaranteed path $guaranteed" ;;
  esac
done

# -- positive proof: the real ReadWritePaths= value, verbatim, lets a
#    ProtectSystem=full unit's mount namespace come up on this host even
#    though /etc/netplan does not exist --
if ! systemd-run --collect --wait --quiet \
    --unit="$UNIT-fixed" \
    --property=ProtectSystem=full \
    --property=PrivateTmp=true \
    --property="ReadWritePaths=$RW_VALUE" \
    /bin/true; then
  fail "the real packaging/alderpointdns.service ReadWritePaths= value fails mount-namespace setup on a host without /etc/netplan -- the fix did not work"
fi

# -- negative control: the same value with the "-" prefixes stripped
#    reproduces the exact reported failure (status=226/NAMESPACE), proving
#    this test would actually catch the regression rather than passing
#    vacuously --
UNPREFIXED_RW_VALUE="$(echo "$RW_VALUE" | tr ' ' '\n' | sed 's/^-//' | tr '\n' ' ')"
if systemd-run --collect --wait --quiet \
    --unit="$UNIT-broken" \
    --property=ProtectSystem=full \
    --property=PrivateTmp=true \
    --property="ReadWritePaths=$UNPREFIXED_RW_VALUE" \
    /bin/true 2>/dev/null; then
  fail "an unprefixed ReadWritePaths= (the pre-fix form) unexpectedly succeeded on this host -- the negative control did not reproduce the reported bug, so the positive proof above is not meaningful"
fi

# -- ProtectSystem=full itself remains enabled, not dropped as a shortcut --
grep -q '^ProtectSystem=full$' /opt/alderpointdns/packaging/alderpointdns.service || \
  fail "packaging/alderpointdns.service no longer sets ProtectSystem=full"

# -- Network Configuration still works for whichever real backend this
#    host actually has, read-only (no live network change attempted here --
#    that is covered separately and is not safe to exercise against a live
#    appliance in this test) --
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/alderpointdns")
from app import network_config as nc

result = nc.read_current_config()
if result["backend"] == nc.BACKEND_UNSUPPORTED:
    sys.exit("FAIL: no supported networking backend detected on this host: " + result["backend_detail"])
if not result["interfaces"]:
    sys.exit("FAIL: read_current_config() found no interfaces")
print(f"detected backend: {result['backend']} ({result['backend_detail']})")
PY

echo "service optional-backend-paths test passed"
