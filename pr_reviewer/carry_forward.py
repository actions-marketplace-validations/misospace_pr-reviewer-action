"""Carry-forward of open findings across incremental reviews (#193).

A full review that requests changes records its findings in the metadata
marker. The next incremental review receives them as "open findings" and the
model must answer each with a resolution (resolved / still_open /
not_verifiable_from_delta). This module applies the deterministic side:
findings the model did not convincingly resolve survive into the new review's
findings array, and a surviving blocker forces request_changes — closing the
one-push amnesia where fixing one of three blockers rubber-stamped the rest.

Fail-closed by design: a carried finding with no matching resolution, or one
the model marked not_verifiable_from_delta, counts as still open.
"""

from __future__ import annotations

import json
from pathlib import Path

# Caps applied when findings are persisted into the metadata marker.
MAX_CARRIED_FINDINGS = 20
MAX_CARRIED_MESSAGE_CHARS = 200

_SEVERITIES = {"blocker", "major", "minor", "info"}
_CATEGORIES = {"bug", "security", "performance", "style", "docs", "question", "other"}


def load_carried_findings(path: str = "previous-findings.json") -> list[dict]:
    """Load and re-sanitize carried findings written by the precheck.

    The marker they came from lives in a PR comment/review body, which is
    attacker-influencable surface, so every field is normalized here even
    though the precheck already sanitized once.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        return []

    carried: list[dict] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        message = item.get("message")
        if not isinstance(message, str) or not message.strip():
            continue
        severity = item.get("severity")
        if severity not in _SEVERITIES:
            severity = "info"
        category = item.get("category")
        if category not in _CATEGORIES:
            category = "other"
        file_path = item.get("file")
        if not isinstance(file_path, str) or not file_path.strip():
            file_path = None
        line = item.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
            line = None
        carried.append(
            {
                "id": f"P{index + 1}",
                "severity": severity,
                "category": category,
                "file": file_path,
                "line": line,
                "message": message.strip()[:MAX_CARRIED_MESSAGE_CHARS],
            }
        )
        if len(carried) >= MAX_CARRIED_FINDINGS:
            break
    return carried


def render_carried_findings_section(carried: list[dict]) -> str:
    """Render the corpus section listing the previous review's open findings."""
    lines = [
        "# Open Findings From the Previous Review",
        "",
        "The previous review of this PR left the findings below open. This",
        "delta review MUST answer each one: include a finding in the findings",
        'array with the same "id" and a "resolution" of "resolved" (this',
        'delta demonstrably fixes it), "still_open", or',
        '"not_verifiable_from_delta". Only claim "resolved" when the delta',
        "diff shows the fix; unverifiable findings stay open.",
        "",
    ]
    for f in carried:
        location = ""
        if f.get("file"):
            location = f" `{f['file']}{':' + str(f['line']) if f.get('line') else ''}`"
        lines.append(f"- [{f['id']}] ({f['severity']}/{f['category']}){location} — {f['message']}")
    return "\n".join(lines) + "\n"


def apply_carry_forward(
    carried_path: str = "previous-findings.json",
    output_path: str = "ai-output.json",
) -> dict:
    """Merge unresolved carried findings into the review output.

    For each carried finding, the model's resolution is looked up by id.
    Findings marked resolved drop out; everything else (still_open,
    not_verifiable_from_delta, or simply unanswered) is merged into the
    output findings array with its original severity. If any surviving
    carried finding is a blocker and the verdict is approve, the verdict is
    forced to request_changes (verdict_source: carry_forward).

    Returns a summary dict: {"carried": n, "resolved": n, "open": n,
    "forced_request_changes": bool}.
    """
    carried = load_carried_findings(carried_path)
    summary = {"carried": len(carried), "resolved": 0, "open": 0, "forced_request_changes": False}
    if not carried:
        return summary

    data = json.loads(Path(output_path).read_text(encoding="utf-8", errors="replace"))
    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []

    resolutions = {
        f["id"]: f.get("resolution")
        for f in findings
        if isinstance(f, dict) and isinstance(f.get("id"), str)
    }

    resolved_items: list[dict] = []
    open_items: list[dict] = []
    for item in carried:
        if resolutions.get(item["id"]) == "resolved":
            resolved_items.append(item)
        else:
            open_items.append(item)
    summary["resolved"] = len(resolved_items)
    summary["open"] = len(open_items)

    # Merge surviving carried findings the model did not re-report itself.
    answered_ids = set(resolutions)
    for item in open_items:
        if item["id"] in answered_ids:
            # The model re-reported it (still_open / not_verifiable) — its
            # entry is already in findings; just ensure severity survived.
            continue
        merged = dict(item)
        merged["resolution"] = "still_open"
        merged["carried_over"] = True
        findings.append(merged)
    for f in findings:
        if isinstance(f, dict) and f.get("id") in {i["id"] for i in open_items}:
            f["carried_over"] = True
    data["findings"] = findings

    # Append an honest cumulative summary to the review body.
    if resolved_items or open_items:
        lines = ["", "", "## Previous Review Findings"]
        if resolved_items:
            lines.append("")
            lines.append("Resolved by this push:")
            lines.extend(f"- [{i['id']}] {i['message']}" for i in resolved_items)
        if open_items:
            lines.append("")
            lines.append("Still open (carried forward):")
            lines.extend(
                f"- [{i['id']}] ({i['severity']}) {i['message']}" for i in open_items
            )
        data["review_markdown"] = str(data.get("review_markdown") or "") + "\n".join(lines)

    # Fail-closed verdict: surviving carried blockers block, regardless of
    # what the delta-only verdict said.
    open_blockers = [i for i in open_items if i["severity"] == "blocker"]
    if open_blockers and data.get("verdict") != "request_changes":
        data["verdict"] = "request_changes"
        data["verdict_source"] = "carry_forward"
        data["review_markdown"] = str(data.get("review_markdown") or "") + (
            "\n\n_Verdict: request_changes — "
            f"{len(open_blockers)} blocker finding(s) from the previous review "
            "remain unresolved (carry-forward is fail-closed)._"
        )
        summary["forced_request_changes"] = True

    Path(output_path).write_text(
        json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary
