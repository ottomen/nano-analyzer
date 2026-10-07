import json
import re

from .constants import SEVERITY_LEVELS

# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------


def _extract_json(text):
    """Try to extract a JSON object or array from text that might have
    markdown fences or surrounding prose."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Repair common nano model JSON malformations (scan output arrays only)
    if '"severity"' in text:
        repaired = text
        # `4: {` instead of `{` in arrays
        repaired = re.sub(r",?\s*\d+\s*:\s*\{", ", {", repaired)
        repaired = re.sub(r"^\[\s*,", "[", repaired.strip())
        # Invalid backslash escapes: \' \0 etc. (not valid in JSON)
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", repaired)
        if repaired != text:
            try:
                return json.loads(repaired)
            except (json.JSONDecodeError, ValueError):
                pass

        # Last resort: extract individual JSON objects from broken arrays
        objects = []
        for m in re.finditer(r'\{\s*"severity"', text):
            depth = 0
            for i in range(m.start(), len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        chunk = text[m.start(): i + 1]
                        chunk = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", chunk)
                        try:
                            objects.append(json.loads(chunk))
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break
        if objects:
            return objects

    for start_char, end_char in [("[", "]"), ("{", "}")]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start: i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def parse_findings(text):
    """Parse findings from JSON array, with fallback to regex."""
    # Method 1: >>> marker lines
    marker_pattern = re.compile(
        r"^>>>\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(.+)",
        re.MULTILINE | re.IGNORECASE,
    )
    marker_matches = list(marker_pattern.finditer(text))
    if marker_matches:
        findings = []
        for m in marker_matches:
            sev = m.group(1).lower()
            rest = m.group(2).strip()
            parts = rest.split("|", 2)
            title = parts[0].strip()
            body = rest
            findings.append({"severity": sev, "title": title, "body": body})
        return findings

    # Method 2: JSON
    parsed = _extract_json(text)

    if isinstance(parsed, dict) and "severity" in parsed:
        parsed = [parsed]

    if isinstance(parsed, dict) and "findings" in parsed:
        parsed = parsed["findings"]

    if isinstance(parsed, list):
        findings = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", "medium").lower()
            if sev == "none":
                continue
            findings.append(
                {
                    "severity": sev,
                    "title": item.get("title", "Untitled finding"),
                    "body": item.get("description", "")
                    + ("\n\nFix: " + item["fix"] if item.get("fix") else ""),
                }
            )
        return findings

    _BUG_KEYWORD = re.compile(
        r"(?:overflow|underflow|use.after.free|double.free|null.pointer|"
        r"null.deref|out.of.bounds|oob|buffer|race|deadlock|"
        r"injection|bypass|escalat|uncheck|missing.check|missing.bound|"
        r"missing.valid|unbounded|unchecked|integer.overflow|"
        r"uaf|memcpy|sprintf|strcpy|strcat|format.string|"
        r"denial.of.service|dos\b|crash|panic|corrupt|"
        r"leak|disclosure|uninitiali|dangling|stale|"
        r"sequence|replay|shift|xdr|length|size)",
        re.IGNORECASE,
    )
    _JUNK_TITLE = re.compile(
        r"(?:^summary|^overview|^what (?:this|to|i) |^threat model|"
        r"^overall|^conclusion|^next step|^recommend|^note|"
        r"^checklist|^audit |^action|^practical |"
        r"^.?level\b|^/info|^.?impact\b|^.?risk\b|"
        r"^.?confidence\b|exploitation path|candidates|"
        r"^concurrency consider|^other |^ssues|^oncrete )",
        re.IGNORECASE,
    )
    # Filter out function-signature headings (documentation, not findings)
    _FUNC_SIG = re.compile(r"^[`\s]*\w+[\w_]*\s*[\(/]", re.IGNORECASE)

    findings = []
    heading_pattern = re.compile(
        r"^#{1,4}\s+"
        r"(?:\d+[\.\)]\s*"  # "## 1) Title" or "## 2. Title"
        r"|(?:critical|high|medium|low)\b"  # "## High severity: ..."
        # "## `function_name()`" or any heading
        r"|[>`\w]"
        r")"
        r"(.*)",
        re.MULTILINE | re.IGNORECASE,
    )
    matches = list(heading_pattern.finditer(text))
    if matches:
        for i, m in enumerate(matches):
            title = m.group(1).strip().strip("*").strip()
            title = re.sub(r"^severity\s*[:/]\s*",
                           "", title, flags=re.IGNORECASE)
            title = re.sub(
                r"^[\(\[]?\s*(?:critical|high|medium|low|informational)\s*[\)\]]?\s*[:/]?\s*",
                "",
                title,
                flags=re.IGNORECASE,
            ).strip()
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            section = text[start:end]
            if _JUNK_TITLE.search(title):
                continue
            if _FUNC_SIG.search(title):
                continue
            if not _BUG_KEYWORD.search(title) and not _BUG_KEYWORD.search(
                section[:300]
            ):
                continue
            sev = "medium"
            for level in SEVERITY_LEVELS:
                if re.search(r"\b" + level + r"\b", section, re.IGNORECASE):
                    sev = level
                    break
            findings.append(
                {"severity": sev, "title": title, "body": section.strip()})

    if not findings:
        for level in SEVERITY_LEVELS:
            if re.search(r"\b" + level + r"\b", text, re.IGNORECASE):
                findings.append(
                    {"severity": level, "title": "Unstructured finding", "body": text}
                )
                break

    return findings


def count_severities(text):
    findings = parse_findings(text)
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return counts


def top_severity(sevs):
    for level in SEVERITY_LEVELS:
        if sevs.get(level, 0) > 0:
            return level
    return "clean"


def extract_findings(report):
    """Extract findings as (title, text) tuples for triage."""
    parsed = parse_findings(report)
    results = []
    for f in parsed:
        fid = f.get("id", "")
        prefix = f"{fid} " if fid else ""
        results.append(
            (
                f"{prefix}{f['title']}",
                f"[{f['severity'].upper()}] {prefix}{f['title']}\n\n{f['body']}",
            )
        )
    return results
