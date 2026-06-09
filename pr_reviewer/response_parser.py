"""Extract and validate JSON from an LLM model response.

Ported from the ``parse_and_validate`` function in ``scripts/run_review.sh``.
Handles multiple response formats (OpenAI choices, Anthropic content blocks,
plain strings) and attempts to recover a JSON object even when surrounded
by markdown code fences or prose.
"""

from __future__ import annotations

import json
from typing import Any


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------

def _extract_content(response: dict[str, Any]) -> str | list[str] | None:
    """Pull the assistant's raw text content from *response*.

    Supports:
    - OpenAI ``choices[0].message.content`` format.
    - Anthropic ``content`` list with ``type == "text"`` blocks.
    - Plain ``content`` string.
    - ``content`` list of strings or dicts with a ``text`` key.
    """
    # OpenAI-style choices array
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message", {})
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    item_type = item.get("type")
                    if item_type in (None, "text"):
                        text_part = item.get("text")
                        if isinstance(text_part, str):
                            parts.append(text_part)
            return parts
        return content

    # Anthropic message response with top-level content list
    content = response.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_val = item.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
        return parts if parts else None

    # Plain string content
    if isinstance(response.get("content"), str):
        return response["content"]

    return None


# ---------------------------------------------------------------------------
# Text normalisation
# ---------------------------------------------------------------------------

def _strip_markdown_code_block(text: str) -> str:
    """Remove surrounding triple-backtick fences if present.

    Only strips when the *entire* text is wrapped in `` ```...``` `` with an
    optional language tag on the opening fence.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines:
            lines = lines[1:]  # skip opening fence (with optional lang)
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]  # skip closing fence
        return "\n".join(lines).strip()
    return stripped


# ---------------------------------------------------------------------------
# JSON recovery
# ---------------------------------------------------------------------------

def _try_decode_json(text: str) -> Any | None:
    """Attempt to decode a JSON object/list from *text*.

    Scans character-by-character for the first ``{`` or ``[`` and tries to
    parse from there, stopping at the first successful decode.  This mirrors
    the shell script's ``for start in range(len(text))`` loop.
    """
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch not in ("{", "["):
            continue
        try:
            obj, _end = decoder.raw_decode(text[i:])
            return obj
        except json.JSONDecodeError:
            continue
    return None


# ---------------------------------------------------------------------------
# Verdict normalisation, truncation, and stream-error detection
# ---------------------------------------------------------------------------

# finish_reason / stop_reason values that indicate the model hit the token cap.
_TRUNCATION_REASONS = {"length", "max_tokens", "max_output_tokens"}

_APPROVE_VERDICTS = {"approve", "approved", "approval", "lgtm"}
_REQUEST_CHANGES_VERDICTS = {
    "request_changes", "request_change", "requestchanges",
    "changes_requested", "change_requested", "needs_changes",
    "needs_change", "reject", "rejected",
}


def _normalize_verdict(value: Any) -> str | None:
    """Map common local-model verdict spellings to the canonical value.

    Weaker models frequently return ``"Approve"``, ``"approved"``,
    ``"request changes"``, ``"REQUEST_CHANGES"`` and similar. Returns
    ``"approve"``, ``"request_changes"``, or ``None`` if unrecognised.
    """
    if not isinstance(value, str):
        return None
    collapsed = "_".join(value.strip().lower().split()).replace("-", "_")
    if collapsed in _APPROVE_VERDICTS:
        return "approve"
    if collapsed in _REQUEST_CHANGES_VERDICTS:
        return "request_changes"
    return None


def _finish_reason(response: dict[str, Any]) -> str | None:
    """Best-effort extraction of the model's stop/finish reason."""
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        fr = choices[0].get("finish_reason")
        if isinstance(fr, str):
            return fr
    sr = response.get("stop_reason")
    if isinstance(sr, str):
        return sr
    return None


def _surface_stream_error(response: dict[str, Any]) -> None:
    """Raise SystemExit if the response carries a transport/stream error.

    The SSE reassembler records provider error events under an ``error`` key so
    a mid-stream error is reported instead of looking like empty output.
    """
    err = response.get("error")
    if not err:
        return
    if isinstance(err, dict):
        msg = err.get("message") or json.dumps(err)
    else:
        msg = str(err)
    raise SystemExit(f"Model endpoint returned an error: {msg}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_response(response: dict[str, Any]) -> dict[str, Any]:
    """Parse an LLM response and return a validated review dict.

    Parameters
    ----------
    response : dict
        The raw JSON response (already deserialised) from the model client.

    Returns
    -------
    dict
        A single JSON object with ``verdict`` and ``review_markdown`` keys.

    Raises
    ------
    SystemExit
        If no JSON can be extracted, or the result is not a dict with the
        expected fields.
    """
    _surface_stream_error(response)

    raw = _extract_content(response)
    if isinstance(raw, list):
        text = "".join(raw).strip()
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        text = ""

    text = _strip_markdown_code_block(text)

    parsed = _try_decode_json(text)

    # Wrap single-item lists: [{"verdict": ...}] → {"verdict": ...}
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        parsed = parsed[0]

    # A truncated generation is the most common cause of parse/validation
    # failure on small local models. Surface it explicitly so the operator
    # knows to raise ai_max_tokens rather than chasing a generic parse error.
    finish = _finish_reason(response)
    trunc = (
        " (model output appears truncated at the token limit; increase ai_max_tokens)"
        if finish in _TRUNCATION_REASONS
        else ""
    )

    if not isinstance(parsed, dict):
        raise SystemExit(
            f"Expected JSON object but got {type(parsed).__name__}{trunc}"
        )

    # Validate required keys
    if "verdict" not in parsed:
        raise SystemExit(f"Parsed JSON missing required key 'verdict'{trunc}")
    if "review_markdown" not in parsed:
        raise SystemExit(f"Parsed JSON missing required key 'review_markdown'{trunc}")

    raw_verdict = parsed.get("verdict")
    verdict = _normalize_verdict(raw_verdict)
    if verdict is None:
        raise SystemExit(
            f"Expected verdict to be 'approve' or 'request_changes', got '{raw_verdict}'"
        )
    # Write back the canonical value so downstream consumers (jq -r '.verdict')
    # always see 'approve' or 'request_changes'.
    parsed["verdict"] = verdict

    markdown = parsed.get("review_markdown")
    if not isinstance(markdown, str) or not markdown.strip():
        raise SystemExit(f"Parsed JSON has empty or missing 'review_markdown'{trunc}")

    return parsed


def parse_response_file(filepath: str) -> dict[str, Any]:
    """Convenience wrapper that reads a JSON file and parses it.

    Parameters
    ----------
    filepath : str
        Path to the response JSON file (e.g. ``ai-output.json``).

    Returns
    -------
    dict
        The validated review dict.
    """
    from pathlib import Path
    raw_text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    response = json.loads(raw_text)
    return parse_response(response)
