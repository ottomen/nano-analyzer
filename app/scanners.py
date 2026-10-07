from pathlib import Path

from .constants import SEVERITY_LEVELS
from .grep import execute_grep_requests
from .helpers import call_llm
from .parsers import count_severities

discovery = Path("prompts/discovery.md")
analysis = Path("prompts/analysis.md")
role = Path("prompts/role.md")
fewshot1 = Path("prompts/fewshots/fewshot1.md")
fewshot2 = Path("prompts/fewshots/fewshot2.md")

DISCOVERY_PROMPT = discovery.read_text(encoding="utf-8")
ANALYSIS_PROMPT = analysis.read_text(encoding="utf-8")
ROLE_PROMPT = role.read_text(encoding="utf-8")
FEWSHOT_1 = fewshot1.read_text(encoding="utf-8")
FEWSHOT_2 = fewshot2.read_text(encoding="utf-8")


def scan_single_file(filepath, code, display_name, model, keys, repo_dir=None):
    """Run the two-stage scan on a single file. Returns result dict."""
    result = {
        "file": filepath,
        "display_name": display_name,
        "model": model,
    }

    try:
        # Stage 1: generate context (with optional grep)
        ctx_messages = [
            {"role": "system", "content": DISCOVERY_PROMPT},
            {"role": "user", "content": f"File: {display_name}\n\n```\n{code}\n```"},
        ]
        context, ctx_usage, ctx_elapsed = call_llm(model, ctx_messages, keys)

        # Execute any grep requests from context generation
        if repo_dir:
            ctx_greps = execute_grep_requests(context, repo_dir)
            if ctx_greps:
                context += f"\n\n[GREP RESULTS from codebase]:\n{ctx_greps}"

        result["context"] = context
        result["context_tokens"] = ctx_usage.get("total_tokens", 0)
        result["context_elapsed"] = round(ctx_elapsed, 1)

        # Stage 2: vulnerability scan (with few-shot example)
        scan_messages = [
            {
                "role": "system",
                "content": ANALYSIS_PROMPT + "\n\n"
                "Security context for the file being analyzed:\n" + context,
            },
            {"role": "user", "content": FEWSHOT_2},
            {"role": "assistant", "content": FEWSHOT_1},
            {
                "role": "user",
                "content": ROLE_PROMPT.format(filepath=display_name, code=code),
            },
        ]
        report, scan_usage, scan_elapsed = call_llm(model, scan_messages, keys)
        result["report"] = report
        result["prompt_tokens"] = scan_usage.get("prompt_tokens", 0)
        result["completion_tokens"] = scan_usage.get("completion_tokens", 0)
        result["total_tokens"] = scan_usage.get("total_tokens", 0)
        result["scan_elapsed"] = round(scan_elapsed, 1)
        result["total_elapsed"] = round(ctx_elapsed + scan_elapsed, 1)
        result["severities"] = count_severities(report)
        result["status"] = "ok"

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["severities"] = {level: 0 for level in SEVERITY_LEVELS}

    return result
