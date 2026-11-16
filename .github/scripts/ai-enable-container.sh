#!/bin/sh
# Runs inside a stock Linux container as root: creates an unprivileged user and
# checks `phase ai enable` on a machine with no system keystore, without and
# with NSS certutil. Env: PHASE (binary path), INSTALL (command that installs
# certutil).
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

# A stock container has no Secret Service, so the CA key is kept in memory
# only: enable must say so, create no CA, and never offer or attempt trust,
# with or without certutil and with or without --trust-ca.
NO_KEYSTORE="no system keystore on this machine"
check_memory_only() {
  echo "$1" | grep -q "$NO_KEYSTORE" || fail "missing no-keystore notice: $1"
  echo "$1" | grep -q "Phase AI CA ready" && fail "a CA was created without a keystore: $1"
  echo "$1" | grep -q "Trust the Phase AI CA" && fail "trust was offered for a memory-only CA: $1"
  echo "$1" | grep -q "Phase AI enabled for Claude Code" || fail "harness not enabled: $1"
  as_user "test ! -e /home/tester/.phase/ai/ca.pem" || fail "enable wrote ca.pem without a keystore"
}
echo "--- stock image"
out="$(as_user "$PHASE ai enable --harness claude-code" 2>&1)" || fail "enable failed: $out"
check_memory_only "$out"
if command -v script >/dev/null 2>&1; then
  echo "--- stock image, interactive terminal"
  out="$(as_user "printf 'y\n' | script -qec '$PHASE ai enable --harness claude-code' /dev/null" 2>&1 | tr -d '\r')" || fail "interactive enable failed: $out"
  check_memory_only "$out"
fi
echo "--- installing certutil: $INSTALL"
sh -c "$INSTALL" >/dev/null 2>&1 || fail "could not install certutil"
out="$(as_user "$PHASE ai enable --harness claude-code --trust-ca" 2>&1)" || fail "enable --trust-ca failed: $out"
check_memory_only "$out"
as_user "grep -rq 'PRIVATE KEY' /home/tester/.phase/ai" && fail "a file under ~/.phase/ai contains private key material"
status="$(as_user "$PHASE ai status" 2>&1)" || fail "status failed: $status"
echo "$status" | grep -q "Phase AI:    enabled" || fail "status not enabled: $status"
echo "OK: ${PRETTY_NAME:-unknown}"
