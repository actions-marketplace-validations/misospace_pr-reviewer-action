#!/usr/bin/env bash
# Model HTTP call helper, sourced by run_review.sh.
#
# Kept in its own file so the curl/HTTP-status handling can be unit-tested
# (tests/test_model_call.sh) — the main driver has no end-to-end harness, and
# this is the part with the subtlest behaviour (transport vs HTTP errors).

# curl_model BASE_URL API_KEY API_FORMAT PAYLOAD_FILE OUTPUT_FILE \
#            [STREAM] [REQUEST_TIMEOUT_SEC] [CONNECT_TIMEOUT_SEC]
#
# Writes the response body to OUTPUT_FILE. Returns:
#   0   on HTTP 2xx/3xx (body in OUTPUT_FILE)
#   22  on HTTP >= 400  (body in OUTPUT_FILE, a redacted head is logged to stderr)
#   N   curl's own non-zero exit code on a transport error (timeout, DNS, reset)
#
# Unlike `curl -f`, the response body is preserved on HTTP errors so a local
# endpoint's "context length exceeded" / "model not found" message is visible
# instead of silently discarded and retried.
curl_model() {
  local base_url="$1" api_key="$2" api_format="$3" payload_file="$4" output_file="$5"
  local stream="${6:-false}" request_timeout_sec="${7:-300}" connect_timeout_sec="${8:-30}"

  local endpoint
  local auth_header=()
  if [[ "$api_format" == "anthropic" ]]; then
    endpoint="$base_url/messages"
    auth_header=( -H "anthropic-version: ${ANTHROPIC_VERSION:-2023-06-01}" )
    if [[ -n "$api_key" ]]; then
      auth_header+=( -H "x-api-key: $api_key" )
    fi
  else
    endpoint="$base_url/chat/completions"
    if [[ -n "$api_key" ]]; then
      auth_header=( -H "Authorization: Bearer $api_key" )
    fi
  fi

  local args=(
    -q
    -sS
    -L
    "$endpoint"
    -H "Content-Type: application/json"
    --data "@$payload_file"
    --max-time "$request_timeout_sec"
    --connect-timeout "$connect_timeout_sec"
    -o "$output_file"
    -w '%{http_code}'
  )

  args+=( "${auth_header[@]}" )

  if [[ "$stream" == "true" ]]; then
    args+=( --no-buffer )
    if [[ "$api_format" == "anthropic" ]]; then
      args+=( -H "Accept: text/event-stream" )
    fi
  fi

  local http_code curl_rc=0
  http_code="$(curl "${args[@]}")" || curl_rc=$?

  if [[ "$curl_rc" -ne 0 ]]; then
    echo "  curl transport error (exit ${curl_rc}) calling model endpoint" >&2
    return "$curl_rc"
  fi

  if [[ "${http_code:-0}" -ge 400 ]]; then
    echo "  model endpoint returned HTTP ${http_code}" >&2
    if [[ -s "$output_file" ]]; then
      # Log a short head so operators can see the real error. Redact obvious
      # credential-looking tokens defensively in case a proxy echoes a header.
      printf '  response body (first 600 bytes): ' >&2
      head -c 600 "$output_file" \
        | sed -E 's/([Bb]earer|x-api-key|api[_-]?key|token|secret)([":= ]+)[A-Za-z0-9._-]+/\1\2[REDACTED]/g' >&2
      echo >&2
    fi
    return 22
  fi

  return 0
}
