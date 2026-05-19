#!/usr/bin/env python3
"""Tool-harness for AI-driven PR review evidence collection."""

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Ensure the scripts directory is on sys.path so we can import shared helpers.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from redact import mask_secrets  # noqa: E402


SENSITIVE_PATH_RE = re.compile(
    r"(^|/)(\.env(\.|$)|id_rsa(\.|$)|id_dsa(\.|$)|credentials(\.|$)|secret(s)?(\.|$)|.*\.pem$|.*\.key$)",
    re.IGNORECASE,
)
GH_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._~/%?&=:+,-]+$")
GH_DENY_SUBSTRINGS = (
    "/actions/secrets",
    "/dependabot/secrets",
    "/environments/",
    "/dispatches",
)


def normalize_repo_name(value):
    text = (value or "").strip().strip("/")
    parts = [item for item in text.split("/") if item]
    if len(parts) != 2:
        return ""
    owner, repo = parts
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner):
        return ""
    if not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        return ""
    return f"{owner}/{repo}"


def env_int(name, default_value, min_value):
    raw = os.getenv(name, str(default_value)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default_value
    return max(min_value, value)


def env_int_bounded(name, default_value, min_value, max_value):
    value = env_int(name, default_value, min_value)
    return min(max_value, value)


def normalize_api_format(value):
    candidate = (value or "openai").strip().lower()
    if candidate in {"openai", "anthropic"}:
        return candidate
    return "openai"


def normalize_host(host):
    return (host or "").strip().lower()


def allowlisted_host(host, allowlist):
    candidate = normalize_host(host)
    for item in allowlist:
        if candidate == item:
            return True
    return False


def truncate_text(text, max_bytes):
    masked = mask_secrets(text)
    raw = masked.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return masked, False
    clipped = raw[:max_bytes].decode("utf-8", errors="replace")
    return clipped + "\n[truncated]", True


def extract_json_object(text):
    data = text.strip()
    if data.startswith("```"):
        lines = data.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        data = "\n".join(lines).strip()

    decoder = json.JSONDecoder()
    parsed = None

    for start in range(len(data)):
        if data[start] not in "[{":
            continue
        try:
            candidate, end = decoder.raw_decode(data[start:])
            parsed = candidate
            break
        except json.JSONDecodeError:
            continue

    if parsed is None:
        raise ValueError("Could not extract JSON object from text")

    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        parsed = parsed[0]

    return parsed


def mask_and_truncate(text, max_bytes):
    masked = mask_secrets(text)
    raw = masked.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return masked, False
    clipped = raw[:max_bytes].decode("utf-8", errors="replace")
    return clipped + "\n[truncated]", True


def fetch_url(url, allowed_hosts):
    """Fetch a URL and return its text content (or None on failure)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""

    if not allowlisted_host(host, allowed_hosts):
        return None

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ai-pr-reviewer/1.0"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return text[:5000]
    except Exception:
        return None


def read_file(path, workspace_root):
    """Read a file with path-traversal protection."""
    resolved = Path(workspace_root) / path
    try:
        resolved = resolved.resolve()
    except OSError:
        return {"error": f"Cannot resolve path: {path}"}

    if not str(resolved).startswith(str(Path(workspace_root).resolve())):
        return {"error": "Path escapes workspace root"}

    if SENSITIVE_PATH_RE.search(resolved.name):
        return {"error": f"Sensitive file blocked: {resolved.name}"}

    for deny in GH_DENY_SUBSTRINGS:
        if deny in str(resolved):
            return {"error": f"Path denied: {deny}"}

    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
        return {"content": content[:12000]}
    except Exception as exc:
        return {"error": str(exc)}


def git_grep(pattern, workspace_root):
    """Run git grep and return matched lines."""
    try:
        result = subprocess.run(
            ["git", "grep", "-n", "--", pattern, "."],
            cwd=workspace_root,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode not in (0, 1):
            return {"error": f"git grep failed: {result.stderr.strip()}"}
        lines = result.stdout.strip().splitlines()[:60]
        return {"matches": lines}
    except subprocess.TimeoutExpired:
        return {"error": "git grep timed out after 15s"}
    except Exception as exc:
        return {"error": str(exc)}


def gh_api(endpoint, allowed_repos, current_repo):
    """Make a GitHub API call with path/endpoint restrictions."""
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN", "")
    if not token:
        return {"error": "Missing GH_TOKEN"}

    # Parse endpoint to extract repo and path
    parts = endpoint.strip("/").split("/")
    if len(parts) < 2:
        return {"error": "Invalid endpoint format: expected owner/repo/..."}

    repo_key = f"{parts[0]}/{parts[1]}"

    # Validate repo is allowed
    allowed = False
    if repo_key == current_repo:
        allowed = True
    elif "*" in allowed_repos:
        allowed = True
    elif repo_key in allowed_repos:
        allowed = True

    if not allowed:
        return {"error": f"Repo not allowed: {repo_key}"}

    # Check for denied path segments
    full_path = "/".join(parts)
    for deny in GH_DENY_SUBSTRINGS:
        if deny in full_path.lower():
            return {"error": f"Path segment denied: {deny}"}

    url = f"https://api.github.com/{full_path}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "ai-pr-reviewer/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
            data = json.loads(raw.decode("utf-8", errors="replace"))
            return {"data": data}
    except urllib.error.HTTPError as exc:
        return {"error": f"GitHub API error: {exc.code} {exc.reason}"}
    except Exception as exc:
        return {"error": str(exc)}


def web_fetch(url, allowed_hosts):
    """Fetch a URL using the same host-allowlist logic."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""

    if not allowlisted_host(host, allowed_hosts):
        return {"error": f"Host not allowlisted: {host}"}

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ai-pr-reviewer/1.0"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return {"content": text[:10000]}
    except Exception as exc:
        return {"error": str(exc)}


def run_command(command, workspace_root):
    """Execute a read-only shell command with path restrictions."""
    # Block dangerous commands
    dangerous = [
        "rm ", "curl ", "wget ", "pip ", "npm install", "apt-get",
        "sudo", "chmod", "chown", "kill ", "exec ", "docker ",
        "kubectl delete", "git push", "git reset --hard",
    ]
    cmd_lower = command.lower()
    for d in dangerous:
        if d in cmd_lower:
            return {"error": f"Command blocked (dangerous pattern): {d}"}

    try:
        result = subprocess.run(
            ["bash", "-lc", command],
            cwd=workspace_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "stdout": mask_secrets((result.stdout or "").strip()),
            "stderr": mask_secrets((result.stderr or "").strip()),
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "error": "Command timed out after 30s",
            "stdout": mask_secrets(
                (exc.stdout or b"").decode("utf-8", errors="replace")
            ),
            "stderr": mask_secrets(
                (exc.stderr or b"").decode("utf-8", errors="replace")
            ),
        }


def main():
    max_response_bytes = int(os.getenv("TOOL_MAX_RESPONSE_BYTES", "12000"))
    planning_timeout = int(os.getenv("TOOL_PLANNING_TIMEOUT_SEC", "30"))
    planning_max_context = int(os.getenv("TOOL_PLANNING_MAX_CONTEXT_BYTES", "50000"))
    request_timeout = int(os.getenv("TOOL_REQUEST_TIMEOUT_SEC", "20"))

    allowed_gh_repos_raw = os.getenv("TOOL_ALLOWED_GH_API_REPOS", "")
    allowed_gh_repos = set()
    if allowed_gh_repos_raw:
        for r in allowed_gh_repos_raw.split(","):
            r = r.strip()
            if r:
                allowed_gh_repos.add(r)

    current_repo = os.getenv("REPO", "")
    allowed_hosts_raw = os.getenv("ALLOWED_SOURCE_HOSTS", "github.com,api.github.com")
    allowed_hosts = [h.strip() for h in allowed_hosts_raw.split(",") if h.strip()]

    workspace_root = os.getcwd()

    result = {
        "mode": "plan_execute_once",
        "planned_request_count": 0,
        "executed_request_count": 0,
        "tool_results": [],
    }

    # Read the planning prompt from tool-planning-input.json
    planning_input_path = Path("tool-planning-input.json")
    if not planning_input_path.exists():
        result["planning_error"] = "Missing tool-planning-input.json"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: no planning input.", encoding="utf-8"
        )
        return 0

    try:
        planning_input = json.loads(planning_input_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result["planning_error"] = f"Invalid planning input: {exc}"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: invalid planning input.", encoding="utf-8"
        )
        return 0

    # Call the planning model to determine which tools to run
    planning_request = {
        "model": os.getenv("AI_MODEL", ""),
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a tool-planning assistant for a PR review system. "
                    "Given the user's request, determine which tools to call and with what arguments. "
                    "Only use these tools: read_file, git_grep, gh_api, web_fetch, run_command. "
                    "read_file: takes 'path' (workspace-relative). "
                    "git_grep: takes 'pattern'. "
                    "gh_api: takes 'endpoint' (e.g., repos/owner/repo/pulls/123). "
                    "web_fetch: takes 'url'. "
                    "run_command: takes 'command' (read-only shell commands only). "
                    "Return a JSON array of tool calls. Each call has 'tool' and 'args'."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(planning_input),
            },
        ],
        "max_tokens": int(os.getenv("TOOL_PLANNING_MAX_TOKENS", "400")),
        "temperature": 0.1,
    }

    # Write planning request and call the model
    Path("tool-planning-request.json").write_text(
        json.dumps(planning_request, indent=2) + "\n", encoding="utf-8"
    )

    # The planning call is made by the parent script; we just parse the output.
    planning_response_path = Path("tool-planning-response.json")
    if not planning_response_path.exists():
        result["planning_error"] = "Missing tool-planning-response.json"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: no planning response.", encoding="utf-8"
        )
        return 0

    try:
        planning_response = json.loads(
            planning_response_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        result["planning_error"] = f"Invalid planning response: {exc}"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: invalid planning response.", encoding="utf-8"
        )
        return 0

    # Extract tool calls from the planning response
    content = None
    if isinstance(planning_response.get("choices"), list):
        content = (
            (planning_response["choices"] or [{}])[0].get("message") or {}
        ).get("content")
    elif isinstance(planning_response.get("content"), str):
        content = planning_response["content"]

    if not content:
        result["planning_error"] = "No content in planning response"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: no planning content.", encoding="utf-8"
        )
        return 0

    # Parse tool calls from the response
    try:
        tool_calls = extract_json_object(content)
    except ValueError as exc:
        result["planning_error"] = str(exc)
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: could not parse tool calls.", encoding="utf-8"
        )
        return 0

    if not isinstance(tool_calls, list):
        result["planning_error"] = "Planning response was not a list of tool calls"
        Path("tool-harness.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        Path("tool-harness.md").write_text(
            "Tool harness skipped: invalid tool call format.", encoding="utf-8"
        )
        return 0

    result["planned_request_count"] = len(tool_calls)

    md_lines = ["# Tool Harness Results", ""]
    md_lines.append(f"**Planned requests:** {result['planned_request_count']}")
    md_lines.append("")

    for i, call in enumerate(tool_calls[:4]):
        tool_name = call.get("tool", "")
        args = call.get("args", {})

        if not isinstance(args, dict):
            args = {}

        tool_result = {"tool": tool_name, "status": "error", "result": {}}

        try:
            if tool_name == "read_file":
                path = args.get("path", "")
                if not path:
                    raise ValueError("Missing 'path' argument")
                res = read_file(path, workspace_root)
                text = mask_secrets(res.get("content", ""))
                text, _ = mask_and_truncate(text, max_response_bytes)
                tool_result["result"] = {"content": text}

            elif tool_name == "git_grep":
                pattern = args.get("pattern", "")
                if not pattern:
                    raise ValueError("Missing 'pattern' argument")
                res = git_grep(pattern, workspace_root)
                matches = res.get("matches", [])
                text = "\n".join(matches)
                text, _ = mask_and_truncate(text, max_response_bytes)
                tool_result["result"] = {"matches": matches[:60]}

            elif tool_name == "gh_api":
                endpoint = args.get("endpoint", "")
                if not endpoint:
                    raise ValueError("Missing 'endpoint' argument")
                res = gh_api(endpoint, allowed_gh_repos, current_repo)
                data = res.get("data")
                text = ""
                if isinstance(data, (dict, list)):
                    text = json.dumps(data, indent=2)[:max_response_bytes]
                tool_result["result"] = {"response": text}

            elif tool_name == "web_fetch":
                url = args.get("url", "")
                if not url:
                    raise ValueError("Missing 'url' argument")
                res = web_fetch(url, allowed_hosts)
                content_text = res.get("content", "")
                text, _ = mask_and_truncate(content_text, max_response_bytes)
                tool_result["result"] = {"content": text}

            elif tool_name == "run_command":
                command = args.get("command", "")
                if not command:
                    raise ValueError("Missing 'command' argument")
                res = run_command(command, workspace_root)
                stdout_text = res.get("stdout", "")
                stderr_text = res.get("stderr", "")
                stdout_text, _ = mask_and_truncate(stdout_text, max_response_bytes)
                stderr_text, _ = mask_and_truncate(stderr_text, max_response_bytes)
                tool_result["result"] = {
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "exit_code": res.get("exit_code"),
                }

            else:
                raise ValueError(f"Unknown tool: {tool_name}")

            tool_result["status"] = "ok"
            result["executed_request_count"] += 1

        except Exception as exc:
            tool_result["result"] = {"error": str(exc)}

        result["tool_results"].append(tool_result)

        md_lines.append(f"## Tool {i + 1}: {tool_name}")
        md_lines.append(f"**Status:** {tool_result['status']}")
        md_lines.append(f"**Arguments:** {json.dumps(args)}")
        if tool_result.get("result"):
            md_lines.append("")
            md_lines.append("```text")
            md_lines.append(json.dumps(tool_result["result"], indent=2)[:3000])
            md_lines.append("```")
        md_lines.append("")

    # Write JSON output
    Path("tool-harness.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Write markdown output (with redaction as a safety net)
    md_content = "\n".join(md_lines)
    md_content = mask_secrets(md_content)
    Path("tool-harness.md").write_text(md_content, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
