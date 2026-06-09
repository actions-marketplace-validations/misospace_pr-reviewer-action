#!/usr/bin/env bash
set -euo pipefail

# Tests for scripts/model_call.sh curl_model(): HTTP-status handling, body
# preservation, and exit-code contract, driven by a mock `curl` on PATH.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/model_call.sh"

PASS=0
FAIL=0
check() {
  local desc="$1" result="$2" expected="$3"
  if [[ "$result" == "$expected" ]]; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc (got '$result', expected '$expected')"
    FAIL=$((FAIL + 1))
  fi
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/bin"

# Mock curl: honours -o <file> and the MOCK_CURL_MODE env var, writes a body,
# prints an HTTP status to stdout (as -w '%{http_code}' would), or fails.
cat > "$TMPDIR/bin/curl" <<'MOCK'
#!/usr/bin/env bash
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
case "${MOCK_CURL_MODE:-ok}" in
  ok)
    [ -n "$out" ] && printf '{"choices":[{"message":{"content":"hi"}}]}' > "$out"
    printf '200'; exit 0 ;;
  http_error)
    [ -n "$out" ] && printf '{"error":{"message":"context length exceeded"}}' > "$out"
    printf '400'; exit 0 ;;
  transport)
    printf '000'; exit 7 ;;
esac
printf '200'; exit 0
MOCK
chmod +x "$TMPDIR/bin/curl"

PAYLOAD="$TMPDIR/payload.json"
echo '{}' > "$PAYLOAD"

run_curl_model() {
  local mode="$1" out="$2"
  (
    PATH="$TMPDIR/bin:$PATH" MOCK_CURL_MODE="$mode" \
      curl_model "http://x/v1" "" "openai" "$PAYLOAD" "$out" "false" "5" "2" >/dev/null 2>&1
  )
}

echo "=== Test: HTTP 200 → rc 0, body written ==="
OUT="$TMPDIR/ok.json"
rc=0; run_curl_model ok "$OUT" || rc=$?
check "rc is 0 on success" "$rc" "0"
check "body written on success" "$([ -s "$OUT" ] && echo yes || echo no)" "yes"

echo ""
echo "=== Test: HTTP 400 → rc 22, error body preserved ==="
OUT="$TMPDIR/err.json"
rc=0; run_curl_model http_error "$OUT" || rc=$?
check "rc is 22 on HTTP >= 400" "$rc" "22"
check "error body preserved (not discarded)" \
  "$(grep -q 'context length exceeded' "$OUT" && echo yes || echo no)" "yes"

echo ""
echo "=== Test: transport error → curl exit code propagated ==="
OUT="$TMPDIR/transport.json"
rc=0; run_curl_model transport "$OUT" || rc=$?
check "rc is 7 (curl transport exit) on connection failure" "$rc" "7"

echo ""
echo "=== Test: error body head is logged on HTTP error ==="
OUT="$TMPDIR/err2.json"
LOG="$(PATH="$TMPDIR/bin:$PATH" MOCK_CURL_MODE=http_error \
  curl_model "http://x/v1" "" "openai" "$PAYLOAD" "$OUT" "false" "5" "2" 2>&1 >/dev/null || true)"
check "HTTP error is logged to stderr" \
  "$(printf '%s' "$LOG" | grep -q 'HTTP 400' && echo yes || echo no)" "yes"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
