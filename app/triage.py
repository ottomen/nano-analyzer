import re
from pathlib import Path

from .helpers import call_llm
from .parsers import _extract_json

triage_template = Path("prompts/triage.md")

TRIAGE_PROMPT = triage_template.read_text(encoding="utf-8")


def triage_finding(
    finding_title,
    finding_text,
    code,
    filepath,
    project_name,
    model,
    keys,
    prior_reasoning=None,
    repo_dir=None,
    reasoning_effort=None,
    file_context=None,
):
    """Stage 3: Skeptical triage of a single finding. Returns verdict dict."""
    prompt = TRIAGE_PROMPT.format(
        project_name=project_name,
        finding=finding_text,
        filepath=filepath,
        code=code,
    )

    if file_context:
        prompt += (
            "\n\n**Security context for this file:**\n"
            + file_context[:2000]  # cap to avoid bloating
        )

    if prior_reasoning:
        prompt += (
            "\n\n---\n\n"
            "Prior reviewers have weighed in below. Their reasoning is "
            "SPECULATIVE — it may contain errors or unfounded assumptions.\n\n"
            "Your job is NOT to repeat their analysis. Instead:\n"
            "- Find arguments they MISSED — new attack paths, new \n"
            "  defenses, different code paths, different callers\n"
            "- If they all focused on one aspect, look at a DIFFERENT one\n"
            "- Verify any cited defense with actual values (use GREP)\n"
            "- Consider angles no prior reviewer raised: what about \n"
            "  error paths? race conditions? integer edge cases? caller \n"
            "  contracts? platform differences?\n"
            "- Do NOT rehash the same argument — add new information\n\n"
        )
        for i, (verdict, reasoning) in enumerate(prior_reasoning, 1):
            prompt += f"**Reviewer {i}**:\n{reasoning}\n\n"

    messages = [
        {
            "role": "system",
            "content": "You are a security engineer triaging "
            "vulnerability reports. For each finding, answer: "
            "(1) Is the bug pattern real in the code? "
            "(2) Can an attacker reach it through untrusted input? Trace "
            "the data flow backward from the bug to its origin. "
            "(3) If a defense is cited, is it actually sufficient? If you "
            "find a numeric constant, grep for its value before concluding. "
            "(4) Even if the bug is real, is it security-relevant? A data "
            "race on diagnostic state, a missing NULL check on an internal "
            "API that only trusted callers use, or undefined behavior only "
            "in debug builds are code quality issues, NOT security "
            "vulnerabilities — mark these INVALID. "
            "Use GREP to verify. Do not guess.",
        },
        {"role": "user", "content": prompt},
    ]

    try:
        response, usage, elapsed = call_llm(
            model, messages, keys, json_mode=True, reasoning_effort=reasoning_effort
        )

        verdict = "UNCERTAIN"
        reasoning = response

        parsed = _extract_json(response)
        if isinstance(parsed, dict):
            v = parsed.get("verdict", "").upper()
            if v in ("VALID", "INVALID", "UNCERTAIN"):
                verdict = v
            reasoning = parsed.get("reasoning", response)
            crux = parsed.get("crux", "")
            if crux:
                reasoning += f"\n\nCRUX: {crux}"

            grep_req = parsed.get("grep", "")
            if grep_req:
                grep_req = re.sub(r"^GREP:\s*", "", grep_req,
                                  flags=re.IGNORECASE)
                grep_req = grep_req.strip("`\"'")
                if grep_req:
                    reasoning += f"\nGREP: {grep_req}"
        else:
            clean = re.sub(r"[*#\-\s]+", " ", response[:300]).strip().upper()
            if "INVALID" in clean[:30]:
                verdict = "INVALID"
            elif "VALID" in clean[:30]:
                verdict = "VALID"
            elif "UNCERTAIN" in clean[:30]:
                verdict = "UNCERTAIN"

        return {
            "finding_title": finding_title,
            "verdict": verdict,
            "reasoning": reasoning,
            "elapsed": round(elapsed, 1),
            "tokens": usage.get("total_tokens", 0),
        }
    except Exception as e:
        return {
            "finding_title": finding_title,
            "verdict": "ERROR",
            "reasoning": str(e),
            "elapsed": 0,
            "tokens": 0,
        }
