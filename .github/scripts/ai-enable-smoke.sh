#!/usr/bin/env bash
# Runs `phase ai enable` end to end on a CI runner and checks the result.
# usage: ai-enable-smoke.sh <phase-binary> <no-trust|trust-nss>
set -euo pipefail
PHASE="$1"; MODE="$2"
HOME_DIR="${HOME:?}"
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$MODE" in
  no-trust)
    output="$("$PHASE" ai enable --harness claude-code --mask --trust-ca=false </dev/null 2>&1)" || fail "enable exited non-zero: $output"
    echo "$output"
    echo "$output" | grep -q "Phase AI CA ready" || fail "CA was not created"
    echo "$output" | grep -q "Phase AI enabled for Claude Code" || fail "harness was not enabled"
    ;;
  trust-nss)
    command -v certutil >/dev/null || fail "certutil is required for trust-nss"
    output="$("$PHASE" ai enable --harness claude-code --mask --trust-ca </dev/null 2>&1)" || fail "enable --trust-ca exited non-zero: $output"
    echo "$output"
    echo "$output" | grep -q "trusted in the Linux current-user NSS database" || fail "CA was not trusted in the NSS database"
    certutil -L -d "sql:$HOME_DIR/.pki/nssdb" | grep -q "Phase AI Proxy CA" || fail "NSS database does not list the Phase CA"
    # A second run must be idempotent.
    second="$("$PHASE" ai enable --harness claude-code --mask --trust-ca </dev/null 2>&1)" || fail "second enable --trust-ca exited non-zero: $second"
    echo "$second" | grep -q "already trusted" || fail "second trust run was not idempotent: $second"
    ;;
  *) fail "unknown mode $MODE" ;;
esac

status="$("$PHASE" ai status 2>&1)"
echo "$status"
echo "$status" | grep -q "Phase AI:    enabled" || fail "status does not report enabled"
echo "$status" | grep -q "^CA:" || fail "status does not report the CA"
[ -f "$HOME_DIR/.phase/ai/ca.pem" ] || fail "ca.pem missing"
grep -q "PRIVATE KEY" "$HOME_DIR/.phase/ai/ca.pem" && fail "ca.pem contains private material"
[ -f "$HOME_DIR/.claude/skills/phase-cli-ai-relay/SKILL.md" ] || fail "runtime skill missing"
[ -f "$HOME_DIR/.claude/skills/phase-cli-app-secrets/SKILL.md" ] || fail "secrets skill missing"
echo "OK: $MODE"
