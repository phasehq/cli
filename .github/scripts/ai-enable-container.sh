#!/bin/sh
# Runs inside a stock Linux container as root: creates an unprivileged user and
# checks `phase ai enable` both without NSS certutil (browser trust must be
# skipped, not fatal) and with it installed (trust must land in the per-user
# NSS database). Env: PHASE (binary path), INSTALL (command that installs certutil).
set -eu
PHASE="${PHASE:?}"; INSTALL="${INSTALL:?}"
. /etc/os-release 2>/dev/null || true; echo "os: ${PRETTY_NAME:-unknown}"
if command -v useradd >/dev/null 2>&1; then useradd -m -s /bin/sh tester; else adduser -D tester; fi
as_user() {
  if command -v runuser >/dev/null 2>&1; then runuser -u tester -- sh -c "export HOME=/home/tester; cd /home/tester; $1"
  elif command -v su >/dev/null 2>&1; then su tester -c "export HOME=/home/tester; cd /home/tester; $1"
  elif command -v setpriv >/dev/null 2>&1; then setpriv --reuid=tester --regid=tester --init-groups sh -c "export HOME=/home/tester; cd /home/tester; $1"
  else chroot --userspec=tester:tester / sh -c "export HOME=/home/tester; cd /home/tester; $1"; fi
}
fail() { echo "FAIL: $*" >&2; exit 1; }
if command -v certutil >/dev/null 2>&1; then fail "image already has certutil; the stock run needs it absent"; fi

echo "--- stock image: browser trust must be skipped without failing"
out="$(as_user "$PHASE ai enable --harness claude-code --mask" 2>&1)" || fail "enable failed without certutil: $out"
echo "$out" | grep -q "Browser CA trust skipped" || fail "missing skip notice: $out"
echo "$out" | grep -q "Phase AI enabled for Claude Code" || fail "harness not enabled: $out"
if command -v script >/dev/null 2>&1; then
  echo "--- stock image, interactive terminal: the trust prompt must not appear"
  out="$(as_user "printf 'y\n' | script -qec '$PHASE ai enable --harness claude-code --mask' /dev/null" 2>&1 | tr -d '\r')" || fail "interactive enable failed: $out"
  echo "$out" | grep -q "Trust the Phase AI CA" && fail "prompt shown although certutil is missing: $out"
  echo "$out" | grep -q "Browser CA trust skipped" || fail "missing skip notice in interactive run: $out"
fi
echo "--- stock image: an explicit --trust-ca fails with the package hint"
if out="$(as_user "$PHASE ai enable --harness claude-code --mask --trust-ca" 2>&1)"; then fail "explicit --trust-ca succeeded without certutil: $out"; fi
echo "$out" | grep -q "NSS certutil is not installed (package" || fail "missing package hint: $out"

echo "--- installing certutil: $INSTALL"
sh -c "$INSTALL" >/dev/null 2>&1 || fail "could not install certutil"
command -v certutil >/dev/null 2>&1 || fail "certutil still missing after install"
out="$(as_user "$PHASE ai enable --harness claude-code --mask --trust-ca" 2>&1)" || fail "enable --trust-ca failed: $out"
echo "$out" | grep -q "trusted in the Linux current-user NSS database" || fail "CA not trusted: $out"
as_user "certutil -L -d sql:/home/tester/.pki/nssdb" | grep -q "Phase AI Proxy CA" || fail "NSS database does not list the Phase CA"
as_user "$PHASE ai enable --harness claude-code --mask --trust-ca" | grep -q "already trusted" || fail "second trust run not idempotent"
as_user "$PHASE ai status" | grep -q "Phase AI:    enabled" || fail "status not enabled"
echo "OK: ${PRETTY_NAME:-unknown}"
