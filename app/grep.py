import os
import re
import shutil
import subprocess
from .constants import MAX_GREP_REQUESTS, MAX_GREP_LINES, MAX_GREP_LINE_LEN


_csearch_path = None
_csearch_index = None
_rg_path = shutil.which("rg")


def init_grep_index(repo_dir):
    """Build a csearch index for the repo if csearch is available."""
    global _csearch_path, _csearch_index, _rg_path
    _csearch_path = shutil.which("csearch")
    cindex_path = shutil.which("cindex")
    _rg_path = shutil.which("rg")

    if not _csearch_path or not cindex_path:
        _csearch_path = None
        return

    _csearch_index = f"/tmp/nano_aisle_{os.path.basename(repo_dir)}.csearchindex"
    if os.path.exists(_csearch_index):
        return

    print(f"📇 Building search index for {repo_dir}...")
    try:
        subprocess.run(
            [cindex_path, repo_dir],
            capture_output=True, timeout=300,
            env={**os.environ, "CSEARCHINDEX": _csearch_index},
        )
        print(f"📇 Index ready: {_csearch_index}")
    except Exception as e:
        print(f"📇 Index failed: {e} — falling back to ripgrep")
        _csearch_path = None


def execute_grep_requests(response_text, repo_dir):
    """Parse grep requests from triage response, execute them, return results.
    Uses csearch if indexed, falls back to ripgrep."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return None

    requests = []

    # Explicit GREP: lines
    for m in re.finditer(r'GREP:\s*(.+)', response_text, re.IGNORECASE):
        requests.append(m.group(1).strip().strip('`').strip())

    # Prose-style: "grep for `pattern`" or "grep for pattern"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?[`"]([^`"]+)[`"]', response_text):
        val = m.group(1).strip()
        if val and val not in requests:
            requests.append(val)

    # Without backticks: "grep for function_name(" or "GREP function_name"
    for m in re.finditer(r'[Gg][Rr][Ee][Pp]\s+(?:for\s+)?(\w[\w_:.*]+\(?)', response_text):
        val = m.group(1).strip()
        if val and len(val) > 6 and val not in requests:
            requests.append(val)

    if not requests:
        return None

    # Junk grep terms the model accidentally produces (from prose near "GREP")
    _GREP_JUNK = {"results", "call", "code", "function", "value",
                  "NULL", "null", "type", "data", "return", "void",
                  "true", "false", "the", "this", "that", "from",
                  "verification", "verifications", "verified", "verify",
                  "evidence", "confirm", "confirmed", "confirms",
                  "output", "outputs", "search", "searches",
                  "pattern", "patterns", "required", "provided",
                  "shown", "needed", "following", "whether",
                  "checked", "checking", "matched", "matches",
                  "returned", "returns", "failed", "missing"}

    def _unescape(s):
        """Strip regex escapes and stray punctuation for literal search."""
        s = re.sub(r'\\[bBdDwWsS]', '', s)
        s = re.sub(r'\\(.)', r'\1', s)
        s = s.strip().strip('"\'`')
        return s

    def _simplify_pattern(pattern):
        """Extract the core identifier from a complex code pattern."""
        identifiers = re.findall(r'[a-zA-Z_]\w*(?:->[\w]+)*', pattern)
        identifiers.sort(key=len, reverse=True)
        for ident in identifiers:
            if len(ident) > 5 and ident not in _GREP_JUNK:
                return ident
        return None

    # Expand compound patterns and clean up
    expanded = []
    for raw in requests[:MAX_GREP_REQUESTS]:
        raw = raw.strip()
        # Split on | and unescape each part
        parts = raw.split("|") if "|" in raw else [raw]
        for part in parts:
            cleaned = _unescape(part)
            if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                continue
            # Strip file path prefixes (e.g. "sys/foo/bar.c:symbol" → "symbol")
            path_prefix = re.match(r'[\w/\\]+\.\w+[:\s]+(.+)', cleaned)
            if path_prefix:
                cleaned = path_prefix.group(1).strip()
                if not cleaned or len(cleaned) < 3 or cleaned in _GREP_JUNK:
                    continue
            # Skip purely numeric patterns (line numbers extracted from file:line refs)
            if re.match(r'^\d+[:\s]*$', cleaned):
                continue
            # If pattern has commas/spaces (too specific), extract identifier
            if ", " in cleaned or len(cleaned) > 60:
                simplified = _simplify_pattern(cleaned)
                if simplified:
                    cleaned = simplified
            expanded.append(cleaned)

    def _run_grep(pattern, repo_dir, fixed=True):
        """Run a single grep, return raw output or empty string."""
        try:
            if _csearch_path and _csearch_index:
                # csearch uses regex — escape special chars for literal match
                escaped = re.escape(pattern) if fixed else pattern
                proc = subprocess.run(
                    [_csearch_path, "-n", escaped],
                    capture_output=True, text=True, timeout=10,
                    env={**os.environ, "CSEARCHINDEX": _csearch_index},
                    errors="replace",
                )
                raw = proc.stdout.strip()
                if raw:
                    raw = raw.replace(repo_dir.rstrip("/") + "/", "")
                    lines_filtered = [l for l in raw.splitlines()
                                      if re.search(r'\.[ch]:', l)]
                    return "\n".join(lines_filtered)
                return ""
            else:
                if not _rg_path:
                    return ""
                flags = ["--fixed-strings"] if fixed else []
                proc = subprocess.run(
                    [_rg_path, "--no-heading", "-n"] + flags +
                    ["-g", "*.c", "-g", "*.h", pattern],
                    capture_output=True, text=True, timeout=60,
                    cwd=repo_dir, errors="replace",
                )
                return proc.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    results = []
    for pattern in expanded[:MAX_GREP_REQUESTS * 2]:
        try:
            # Detect if pattern uses regex syntax
            is_regex = bool(re.search(r'(?<![\\])[.*+?{}|^$]', pattern))

            # Try search
            raw = _run_grep(pattern, repo_dir, fixed=not is_regex)

            # If no results and pattern looks complex, simplify and retry
            if not raw and any(c in pattern for c in "(),-> "):
                simplified = _simplify_pattern(pattern)
                if simplified and simplified != pattern:
                    raw = _run_grep(simplified, repo_dir, fixed=True)
                    if raw:
                        pattern = f"{pattern} (simplified to: {simplified})"

            all_lines = raw.splitlines() if raw else []
            # Prioritize #define and .h lines (definitions) over usage sites

            def _line_priority(l):
                if '#define' in l:
                    return 0
                if '.h:' in l:
                    return 1
                return 2
            all_lines.sort(key=_line_priority)
            lines = all_lines[:MAX_GREP_LINES]
            truncated = []
            for line in lines:
                if len(line) > MAX_GREP_LINE_LEN:
                    truncated.append(line[:MAX_GREP_LINE_LEN] + "...")
                else:
                    truncated.append(line)
            output = "\n".join(
                truncated) if truncated else "(no matches in repo)"
            output = output.replace("\x00", "")
            results.append(f"GREP `{pattern}`:\n```\n{output}\n```")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results.append(f"GREP `{pattern}`: (search failed)")

    return "\n\n".join(results)
