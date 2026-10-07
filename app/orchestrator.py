import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from dotenv import load_dotenv

from .constants import DEFAULT_EXTENSIONS, SEVERITY_LEVELS, VERDICT_EMOJI
from .discovery import discover_files
from .grep import execute_grep_requests, init_grep_index
from .helpers import call_llm, init_api_semaphore, load_api_keys
from .parsers import _extract_json, extract_findings, parse_findings
from .scanners import scan_single_file
from .triage import triage_finding

load_dotenv()

VERSION = os.getenv("VERSION")


def _condense_prior_greps(reasoning_text, max_lines_per_pattern=3):
    """Replace full grep output in prior-round reasoning with a compact
    summary that preserves key evidence without context bloat."""
    match = re.search(r"\n\n\[GREP RESULTS[^\]]*\]:\n", reasoning_text)
    if not match:
        return reasoning_text

    before = reasoning_text[: match.start()]
    grep_section = reasoning_text[match.end():]

    condensed = []
    for pattern, content in re.findall(
        r"GREP `([^`]*)`:\n```\n(.*?)\n```", grep_section, re.DOTALL
    ):
        content = content.strip()
        if not content or content == "(no matches in repo)":
            condensed.append(f"  - `{pattern}`: (no matches)")
        else:
            lines = [l for l in content.split("\n") if l.strip()]
            shown = lines[:max_lines_per_pattern]
            extra = len(lines) - len(shown)
            for line in shown:
                condensed.append(f"  - {line.strip()}")
            if extra > 0:
                condensed.append(f"    (+{extra} more matches)")

    if condensed:
        return before + "\n\n[Prior grep evidence]:\n" + "\n".join(condensed)
    return before


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


print_lock = threading.Lock()


def print_logo(offset_spaces: int = 5) -> str:
    logo_str = f"""\033[32m
            I   I
           AI   IA
         AA#I   I#AA
       AA##V     V##AA
     AA###V       V###AA
   AA####V         V####AA
TTT#####V           V#####TTT
III####V             V####III
III###V               V###III
III##V  \033[30mNANO-ANALYZER\033[32m  V##III
III#V    \033[90mversion \033[30m{VERSION}    \033[32mV#III
IIIV                     VIII
          \033[92mA I S L E
    \033[0m"""

    logo_str = "".join(
        [f"{' ' * offset_spaces}{line}\n" for line in logo_str.split("\n")]
    )

    print(logo_str)

    return logo_str


def run_scan(args):
    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    init_api_semaphore(max_conn)
    keys = load_api_keys()

    # Discover files
    ext_set = DEFAULT_EXTENSIONS

    scannable, skipped = discover_files(args.path, ext_set, args.max_chars)

    if not scannable:
        print("❌ No scannable files found.")
        return

    total_lines = sum(f["lines"] for f in scannable)
    total_chars = sum(f["chars"] for f in scannable)

    # Compute display base for relative paths
    if os.path.isdir(args.path):
        base_path = os.path.abspath(args.path)
    else:
        base_path = os.path.dirname(os.path.abspath(args.path))

    # Resolve grep/repo directory
    if args.repo_dir:
        repo_dir = args.repo_dir
    elif os.path.isfile(args.path):
        repo_dir = os.path.dirname(os.path.abspath(args.path))
    else:
        repo_dir = os.path.abspath(args.path)

    # Timestamp for output directory
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    if args.output_dir:
        out_dir = args.output_dir
    else:
        out_dir = os.path.join(
            os.path.expanduser("./analyzer-results"),
            timestamp,
        )
    os.makedirs(out_dir, exist_ok=True)

    # Triage config
    triage_threshold = args.triage_threshold
    triage_rounds = args.triage_rounds
    project_name = args.project or os.path.basename(os.path.abspath(args.path))
    if args.repo_dir:
        init_grep_index(repo_dir)
    do_triage = triage_threshold is not None
    verbose_triage = args.verbose_triage
    thresh_idx = SEVERITY_LEVELS.index(triage_threshold) if do_triage else -1
    triage_counter = [0]  # completed triages
    # total triages submitted (grows as scans find findings)
    triage_total = [0]
    triage_semaphore = threading.Semaphore(
        args.triage_parallel) if do_triage else None
    active_scans = [0]
    active_triages = [0]
    triage_valid_count = [0]
    triage_invalid_count = [0]
    triage_uncertain_count = [0]

    # Pre-scan summary
    print_logo()
    print("nano-analyzer vulnerability scanner started")
    print(f"➜ Target: {os.path.abspath(args.path)}")
    print(f"➜ Grep dir: {repo_dir}")
    print(
        f"➜ {len(scannable)} files to scan ({total_lines:,} lines, {total_chars:,} chars)"
    )
    if skipped:
        skip_ext = sum(1 for _, r in skipped if r == "extension")
        skip_size = sum(1 for _, r in skipped if "large" in r)
        skip_other = len(skipped) - skip_ext - skip_size
        parts = []
        if skip_ext:
            parts.append(f"{skip_ext} wrong extension")
        if skip_size:
            parts.append(f"{skip_size} too large")
        if skip_other:
            parts.append(f"{skip_other} unreadable")
        print(f"   ⏭️  {len(skipped)} skipped ({', '.join(parts)})")
    print(f"➜ Model: {args.model}")
    print(
        f"➜ Parallelism: {args.parallel} scan, {args.triage_parallel} triage")
    print(f"➜ Results: {out_dir}/")
    if do_triage:
        rounds_str = f", {triage_rounds} rounds" if triage_rounds > 1 else ""
        print(
            f"➜ Triage: {triage_threshold}+ findings → skeptical review ({rounds_str.lstrip(', ')})"
            if triage_rounds > 1
            else f"➜ Triage: {triage_threshold}+ findings → skeptical review"
        )
    print()

    # Run scans (and inline triage)
    results = []
    all_triage_results = []
    completed = 0
    total = len(scannable)
    scan_start = time.time()

    def process_file(file_info):
        nonlocal completed
        filepath = file_info["filepath"]

        with open(filepath) as f:
            code = f.read()

        display_name = os.path.relpath(filepath, base_path)

        with print_lock:
            active_scans[0] += 1
        try:
            result = scan_single_file(
                filepath,
                code,
                display_name,
                args.model,
                keys,
                repo_dir=repo_dir,
            )
        finally:
            with print_lock:
                active_scans[0] -= 1

        result["lines"] = file_info["lines"]
        result["chars"] = file_info["chars"]
        result["timestamp"] = timestamp

        # Save individual results
        safename = display_name.replace("/", "_").replace("\\", "_")
        md_path = os.path.join(out_dir, f"{safename}.md")
        json_path = os.path.join(out_dir, f"{safename}.json")

        if result["status"] == "ok":
            with open(md_path, "w") as f:
                f.write(f"# Scan: {display_name}\n\n")
                f.write(result["report"])

            ctx_md_path = os.path.join(out_dir, f"{safename}.context.md")
            with open(ctx_md_path, "w") as f:
                f.write(f"# Context: {display_name}\n\n")
                f.write(result.get("context", "(no context generated)"))

            with open(json_path, "w") as f:
                json.dump(result, f, indent=2)

        # Live scan output
        with print_lock:
            completed += 1
            sevs = result["severities"]
            short_name = os.path.basename(filepath)
            elapsed = result.get("total_elapsed", 0)
            cw = len(str(total))

            sc = active_scans[0]
            tc = active_triages[0]
            ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
            load = f"[LLMs running S:{sc} T:{tc}]"

            if result["status"] == "error":
                print(
                    f"  {ts} [file {completed:>{cw}}/{total}] ❌ {short_name}  ERROR: {result['error'][:50]}  {load}"
                )
            else:
                dots = ""
                for lev, em in [
                    ("critical", "🔴"),
                    ("high", "🟠"),
                    ("medium", "🟡"),
                    ("low", "🔵"),
                ]:
                    dots += em * sevs.get(lev, 0)

                ctx_link = os.path.join(out_dir, f"{safename}.context.md")
                scan_link = os.path.join(out_dir, f"{safename}.md")
                if dots:
                    print(
                        f"  {ts} [file {completed:>{cw}}/{total}] {dots} {short_name}  {elapsed:.0f}s  {load}"
                    )
                else:
                    print(
                        f"  {ts} [file {completed:>{cw}}/{total}] {short_name}  {elapsed:.0f}s  {load}"
                    )
                if result["status"] == "ok":
                    print(f"          {ctx_link}")
                    print(f"          {scan_link}")

        # Queue triage work (non-blocking — fires and forgets into triage executor)
        result["_triage_pending"] = []
        if do_triage and result["status"] == "ok":
            needs_triage = any(
                result["severities"].get(lev, 0) > 0
                for lev in SEVERITY_LEVELS[: thresh_idx + 1]
            )
            if needs_triage:
                findings = extract_findings(result["report"])
                to_triage = []
                for title, text in findings:
                    finding_sev = None
                    for lev in SEVERITY_LEVELS:
                        if re.search(r"\b" + lev + r"\b", text[:200], re.IGNORECASE):
                            finding_sev = lev
                            break
                    if (
                        finding_sev is None
                        or SEVERITY_LEVELS.index(finding_sev) > thresh_idx
                    ):
                        continue
                    to_triage.append((title, text))

                file_context = result.get("context", "")

                def _triage_one_finding(t_title, t_text, t_code, t_display, t_short):
                    """Run all triage rounds for one finding, print result, append."""
                    try:
                        return _triage_one_finding_inner(
                            t_title, t_text, t_code, t_display, t_short
                        )
                    except Exception as e:
                        with print_lock:
                            ts = datetime.now(
                                tz=timezone.utc).strftime("%H:%M:%S")
                            print(
                                f"  {ts} ❌ TRIAGE ERROR {t_short}: {t_title[:40]}... — {e}"
                            )

                def _triage_one_finding_inner(
                    t_title, t_text, t_code, t_display, t_short
                ):
                    round_verdicts = []
                    prior = None
                    for rn in range(1, triage_rounds + 1):
                        with triage_semaphore:
                            with print_lock:
                                active_triages[0] += 1
                            try:
                                tv = triage_finding(
                                    t_title,
                                    t_text,
                                    t_code,
                                    t_display,
                                    project_name,
                                    args.model,
                                    keys,
                                    prior_reasoning=prior,
                                    repo_dir=repo_dir,
                                    file_context=file_context,
                                )
                            except Exception as e:
                                tv = {
                                    "finding_title": t_title,
                                    "verdict": "UNCERTAIN",
                                    "reasoning": f"Triage error: {e}",
                                }
                            finally:
                                with print_lock:
                                    active_triages[0] -= 1
                        tv["file"] = t_display
                        tv["round"] = rn
                        round_verdicts.append(tv)

                        # Print partial progress per round
                        if triage_rounds > 1 and verbose_triage:
                            history = "".join(
                                VERDICT_EMOJI.get(rv["verdict"], "❓")
                                for rv in round_verdicts
                            )
                            with print_lock:
                                sc = active_scans[0]
                                at = active_triages[0]
                                ts = datetime.now(
                                    tz=timezone.utc).strftime("%H:%M:%S")
                                short_t = (
                                    t_title[:35] + "..."
                                    if len(t_title) > 35
                                    else t_title
                                )
                                print(
                                    f"  {ts}    R{rn}/{triage_rounds} {history} {t_short}: {short_t}  [LLMs running S:{sc} T:{at}]"
                                )

                        if prior is None:
                            prior = []

                        reasoning_text = tv.get("reasoning", "")

                        # Execute any GREP requests from this round
                        grep_results = execute_grep_requests(
                            reasoning_text, repo_dir)
                        if grep_results:
                            tv["grep_used"] = True
                            tv["grep_results"] = grep_results

                        # Condense grep results from older rounds to save
                        # context while preserving key evidence for later rounds
                        if prior:
                            prior = [(v, _condense_prior_greps(r))
                                     for v, r in prior]

                        reasoning_with_greps = reasoning_text
                        if grep_results:
                            reasoning_with_greps += (
                                f"\n\n[GREP RESULTS]:\n{grep_results}"
                            )
                        prior.append((tv["verdict"], reasoning_with_greps))

                    n_valid = sum(
                        1 for rv in round_verdicts if rv["verdict"] == "VALID"
                    )
                    n_invalid = sum(
                        1 for rv in round_verdicts if rv["verdict"] == "INVALID"
                    )
                    n_total = len(round_verdicts)
                    any_greps = any(rv.get("grep_used")
                                    for rv in round_verdicts)
                    confidence = n_valid / n_total if n_total > 0 else 0
                    verdicts_str = "".join(rv["verdict"][0]
                                           for rv in round_verdicts)

                    # Final arbiter: fresh call with just the key facts
                    if triage_rounds > 1:
                        # Collect reasoning summaries and grep results
                        evidence = []
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "?")
                            reasoning = rv.get("reasoning", "")
                            # Include first ~500 chars of reasoning + crux
                            summary = reasoning[:500]
                            if len(reasoning) > 500:
                                summary += "..."
                            crux_m = re.search(
                                r"CRUX:\s*(.+?)(?:\n|$)", reasoning)
                            crux = (
                                f"\nCRUX: {crux_m.group(1).strip()}" if crux_m else ""
                            )
                            evidence.append(
                                f"**Round {rv.get('round', '?')} ({rv_emoji} {rv['verdict']}):** "
                                f"{summary}{crux}"
                            )
                            if rv.get("grep_results"):
                                evidence.append(rv["grep_results"])

                        arbiter_prompt = (
                            f"A vulnerability was reported in {project_name}:\n"
                            f"{t_title}\n\n"
                            f"The reported finding:\n{t_text}\n\n"
                            f"Key evidence from {n_total} rounds of analysis:\n"
                            + "\n".join(evidence[:10])
                            + "\n\n"
                            f"Verdicts so far: {verdicts_str} "
                            f"({n_valid} valid, {n_invalid} invalid)\n\n"
                            f"The relevant source code from {t_display}:\n"
                            f"```c\n{t_code}\n```\n\n"
                            "Based on the code and evidence, is this a "
                            "real security vulnerability? Verify any "
                            "numeric values yourself from the code.\n\n"
                            + (
                                f"NOTE: All {n_total} prior reviewers said "
                                "UNCERTAIN or INVALID. Only override to VALID "
                                "if the evidence is overwhelming and you can "
                                "justify it clearly.\n\n"
                                if n_valid == 0
                                else ""
                            )
                            + "Respond with JSON: "
                            '{"verdict": "VALID/INVALID", '
                            '"reasoning": "concise explanation"}'
                        )
                        try:
                            with triage_semaphore:
                                with print_lock:
                                    active_triages[0] += 1
                                try:
                                    arbiter_resp, _, _ = call_llm(
                                        args.model,
                                        [
                                            {
                                                "role": "system",
                                                "content": "You are an impartial judge. "
                                                "Decide based on evidence, not arguments.",
                                            },
                                            {"role": "user",
                                                "content": arbiter_prompt},
                                        ],
                                        keys,
                                        json_mode=True,
                                    )
                                finally:
                                    with print_lock:
                                        active_triages[0] -= 1

                            arbiter_parsed = _extract_json(arbiter_resp)
                            if isinstance(arbiter_parsed, dict):
                                arbiter_verdict = arbiter_parsed.get(
                                    "verdict", ""
                                ).upper()
                                if arbiter_verdict in ("VALID", "INVALID"):
                                    round_verdicts.append(
                                        {
                                            "verdict": arbiter_verdict,
                                            "reasoning": f"[ARBITER] {arbiter_parsed.get('reasoning', '')}",
                                            "round": n_total + 1,
                                            "file": t_display,
                                            "finding_title": t_title,
                                        }
                                    )
                                    verdicts_str += "→" + arbiter_verdict[0]
                                    if arbiter_verdict == "VALID":
                                        n_valid += 1
                                    else:
                                        n_invalid += 1
                                    n_total += 1
                                    confidence = n_valid / n_total
                        except Exception:
                            pass  # arbiter failure is non-fatal

                    final_tv = round_verdicts[-1].copy()
                    final_tv["all_rounds"] = round_verdicts
                    final_tv["confidence"] = round(confidence, 2)
                    final_tv["verdicts_str"] = verdicts_str
                    final_tv["verdict"] = round_verdicts[-1]["verdict"]

                    short_title = final_tv["finding_title"]
                    if len(short_title) > 45:
                        short_title = short_title[:42] + "..."
                    emoji = VERDICT_EMOJI.get(final_tv["verdict"], "❓")
                    conf_pct = int(confidence * 100)

                    # Write triage detail file
                    triage_dir = os.path.join(out_dir, "triages")
                    os.makedirs(triage_dir, exist_ok=True)
                    safe_file = t_display.replace("/", "_").replace("\\", "_")
                    safe_title = re.sub(
                        r"[^\w\-]", "_", final_tv["finding_title"][:40]
                    ).strip("_")

                    with print_lock:
                        triage_counter[0] += 1
                        tc = triage_counter[0]
                        tt = triage_total[0]

                    triage_md = os.path.join(
                        triage_dir, f"T{tc:04d}_{safe_file}_{safe_title}.md"
                    )
                    with open(triage_md, "w") as tf:
                        tf.write(
                            f"# Triage T{tc:04d}: {final_tv['finding_title']}\n\n")
                        tf.write(f"- **File**: `{t_display}`\n")
                        tf.write(f"- **Verdict**: {final_tv['verdict']}\n")
                        tf.write(
                            f"- **Confidence**: {conf_pct}% [{verdicts_str}]\n\n")
                        tf.write("---\n\n## Finding\n\n")
                        tf.write(final_tv.get("finding_title", ""))
                        tf.write("\n\n---\n\n## Triage rounds\n\n")
                        for rv in round_verdicts:
                            rv_emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                            tf.write(
                                f"### Round {rv['round']}: {rv_emoji} {rv['verdict']}\n\n"
                            )
                            reasoning = rv.get("reasoning", "")
                            # Extract and highlight crux
                            crux_match = re.search(
                                r"CRUX:\s*(.+?)(?:\n|$)", reasoning)
                            if crux_match:
                                tf.write(
                                    f"**🎯 Crux:** {crux_match.group(1).strip()}\n\n"
                                )
                            tf.write(reasoning)
                            if rv.get("grep_results"):
                                tf.write(
                                    f"\n\n🔎 **Grep results:**\n\n{rv['grep_results']}"
                                )
                            tf.write("\n\n")

                    final_tv["triage_md"] = triage_md

                    with print_lock:
                        sc = active_scans[0]
                        at = active_triages[0]
                        ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
                        load = f"[LLMs running S:{sc} T:{at}]"
                        grep_icon = " 🔎" if any_greps else ""
                        if triage_rounds > 1:
                            print(
                                f"  {ts} 🔬 [triage {tc}/{tt}] {emoji} {conf_pct}% [{verdicts_str}]{grep_icon} {t_short}: {short_title}  {load}"
                            )
                        else:
                            print(
                                f"  {ts} 🔬 [triage {tc}/{tt}] {emoji}{grep_icon} {t_short}: {short_title}  {load}"
                            )
                        print(f"         📄 {triage_md}")

                        if final_tv["verdict"] == "VALID":
                            triage_valid_count[0] += 1
                        elif final_tv["verdict"] == "INVALID":
                            triage_invalid_count[0] += 1
                        else:
                            triage_uncertain_count[0] += 1

                        _show_every = 25 if tt > 100 else 10
                        if tc > 1 and tc % _show_every == 0:
                            _el = time.time() - scan_start
                            _v = triage_valid_count[0]
                            _i = triage_invalid_count[0]
                            _u = triage_uncertain_count[0]
                            _rate = tc / _el * 60 if _el > 0 else 0
                            print(f"\n  {'─' * 58}")
                            print(
                                f"  📊 Triage: triage {tc}/{tt} done  ⏱️ {_el:.0f}s  ({_rate:.1f}/min)"
                            )
                            print(
                                f"     ✅ {_v} valid   ❌ {_i} rejected   ❓ {_u} uncertain"
                            )
                            print(f"  {'─' * 58}\n")

                    all_triage_results.append(final_tv)

                for fi, (title, text) in enumerate(to_triage):
                    with print_lock:
                        triage_total[0] += 1
                    triage_executor.submit(
                        _triage_one_finding,
                        title,
                        text,
                        code,
                        display_name,
                        short_name,
                    )

        return result

    max_conn = args.max_connections or (args.parallel + args.triage_parallel)
    triage_executor = ThreadPoolExecutor(
        max_workers=max_conn) if do_triage else None

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {executor.submit(process_file, fi): fi for fi in scannable}
        for future in as_completed(futures):
            results.append(future.result())

    # Scans done — release scan capacity into the triage semaphore so
    # triage can use all available connections.
    if triage_executor:
        if triage_semaphore:
            for _ in range(args.parallel):
                triage_semaphore.release()
        remaining = triage_total[0] - triage_counter[0]
        if remaining > 0:
            max_conn = args.max_connections or (
                args.parallel + args.triage_parallel)
            print(
                f"\n⏳ Scans complete. {remaining} triages remaining (full capacity: {max_conn} connections)..."
            )
        triage_executor.shutdown(wait=True)

    wall_time = time.time() - scan_start

    # Sort results by severity for summary
    results.sort(
        key=lambda r: (
            -r["severities"].get("critical", 0),
            -r["severities"].get("high", 0),
            -r["severities"].get("medium", 0),
        )
    )

    # Summary
    crit_files = [r for r in results if r["severities"].get("critical", 0) > 0]
    high_files = [
        r for r in results if r["severities"].get("high", 0) > 0 and r not in crit_files
    ]
    med_files = [
        r
        for r in results
        if r["severities"].get("medium", 0) > 0
        and r not in crit_files
        and r not in high_files
    ]
    clean_files = [
        r for r in results if sum(r["severities"].values()) == 0 and r["status"] == "ok"
    ]
    error_files = [r for r in results if r["status"] == "error"]

    print()
    print("━" * 60)
    print(f"📊 Summary: {len(results)} files scanned in {wall_time:.0f}s")
    if crit_files:
        crit_total = sum(r["severities"]["critical"] for r in crit_files)
        print(
            f"   🔴 Critical: {len(crit_files)} files ({crit_total} findings)")
        for r in crit_files:
            print(f"      → {r['display_name']}")
    if high_files:
        high_total = sum(r["severities"]["high"] for r in high_files)
        print(
            f"   🟠 High:     {len(high_files)} files ({high_total} findings)")
    if med_files:
        print(f"   🟡 Medium:   {len(med_files)} files")
    print(f"   🟢 Clean:    {len(clean_files)} files")
    if error_files:
        print(f"   ❌ Errors:   {len(error_files)} files")
    print(f"💾 Results saved to: {out_dir}/")

    # Triage summary
    if all_triage_results:
        valid_count = sum(
            1 for t in all_triage_results if t["verdict"] == "VALID")
        invalid_count = sum(
            1 for t in all_triage_results if t["verdict"] == "INVALID")
        uncertain_count = sum(
            1 for t in all_triage_results if t["verdict"] == "UNCERTAIN"
        )

        print()
        print(
            f"🔬 Triage: ✅ {valid_count} valid | ❌ {invalid_count} rejected | ❓ {uncertain_count} uncertain"
        )

        if valid_count > 0:
            print()
            survivors = sorted(
                [t for t in all_triage_results if t["verdict"] == "VALID"],
                key=lambda t: -t.get("confidence", 1),
            )
            min_conf = args.min_confidence
            if min_conf > 0:
                survivors = [t for t in survivors if t.get(
                    "confidence", 1) >= min_conf]

            if survivors:
                print("   🚨 Findings that survived triage:")
            else:
                print("   🟢 No findings above confidence threshold.")

            findings_dir = os.path.join(out_dir, "findings")
            os.makedirs(findings_dir, exist_ok=True)

            for idx, t in enumerate(survivors, 1):
                safename = t["file"].replace("/", "_").replace("\\", "_")
                conf = t.get("confidence", 1)
                conf_pct = int(conf * 100)

                if conf >= 0.9:
                    bar = "🔥"
                elif conf >= 0.7:
                    bar = "✅"
                elif conf >= 0.5:
                    bar = "🤔"
                else:
                    bar = "❓"

                finding_filename = f"VULN-{idx:03d}_{safename}.md"
                finding_path = os.path.join(findings_dir, finding_filename)

                with open(finding_path, "w") as ff:
                    ff.write(f"# VULN-{idx:03d}: {t['finding_title']}\n\n")
                    ff.write(f"- **File**: `{t['file']}`\n")
                    ff.write(f"- **Confidence**: {conf_pct}%")
                    vs = t.get("verdicts_str", "")
                    if vs:
                        ff.write(f" [{vs}]")
                    ff.write("\n")
                    ff.write(f"- **Project**: {project_name}\n")
                    ff.write(f"- **Date**: {timestamp}\n\n")
                    ff.write("---\n\n")
                    ff.write("## Scanner finding\n\n")
                    all_rounds = t.get("all_rounds", [])
                    if all_rounds:
                        ff.write(all_rounds[0].get("finding_title", ""))
                        ff.write("\n\n")
                        body = next(
                            (
                                f["body"]
                                for f in parse_findings(
                                    next(
                                        (
                                            r["report"]
                                            for r in results
                                            if r.get("display_name") == t["file"]
                                        ),
                                        "",
                                    )
                                )
                                if f["title"] in t["finding_title"]
                                or t["finding_title"] in f["title"]
                            ),
                            None,
                        )
                        if body:
                            ff.write(body)
                            ff.write("\n\n")
                    ff.write("---\n\n")
                    ff.write("## Triage reasoning\n\n")
                    for ri, rv in enumerate(all_rounds, 1):
                        emoji = VERDICT_EMOJI.get(rv["verdict"], "❓")
                        ff.write(
                            f"### Round {ri}: {emoji} {rv['verdict']}\n\n")
                        ff.write(rv.get("reasoning", ""))
                        ff.write("\n\n")

                vs = t.get("verdicts_str", "")
                arbiter_str = ""
                if "→" in vs:
                    arbiter_v = vs.split("→")[-1]
                    arbiter_emoji = {"V": "✅", "I": "❌"}.get(arbiter_v, "❓")
                    arbiter_str = f" (arbiter: {arbiter_emoji})"
                print(
                    f"      {bar} {conf_pct}% [{vs}]{arbiter_str} {t['file']}: {t['finding_title']}"
                )
                print(f"         📄 {finding_path}")

        with open(os.path.join(out_dir, "triage.json"), "w") as f:
            json.dump(all_triage_results, f, indent=2)

        triage_md_path = os.path.join(out_dir, "triage_survivors.md")
        with open(triage_md_path, "w") as f:
            f.write("# nano-analyzer triage survivors\n\n")
            f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
            f.write(f"- **Date**: {timestamp}\n")
            f.write(f"- **Model**: {args.model}\n")
            f.write(f"- **Threshold**: {triage_threshold}+\n")
            f.write(
                f"- **Results**: ✅ {valid_count} valid | "
                f"❌ {invalid_count} rejected | "
                f"❓ {uncertain_count} uncertain\n\n"
            )
            f.write("---\n\n")
            for t in all_triage_results:
                if t["verdict"] != "VALID":
                    continue
                f.write(f"## ✅ {t['file']}: {t['finding_title']}\n\n")
                f.write("**Verdict**: VALID\n\n")
                f.write("### Triage reasoning\n\n")
                f.write(t["reasoning"])
                f.write("\n\n---\n\n")

        print(f"\n   📄 Triage writeup: {triage_md_path}")

    # Save summary
    summary = {
        "timestamp": timestamp,
        "target": os.path.abspath(args.path),
        "model": args.model,
        "files_scanned": len(results),
        "total_lines": total_lines,
        "wall_time_seconds": round(wall_time, 1),
        "files_skipped": len(skipped),
        "critical_files": len(crit_files),
        "high_files": len(high_files),
        "clean_files": len(clean_files),
        "error_files": len(error_files),
        "per_file": [
            {
                "file": r["display_name"],
                "lines": r.get("lines", 0),
                "severities": r["severities"],
                "status": r["status"],
                "elapsed": r.get("total_elapsed", 0),
            }
            for r in results
        ],
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Human-readable summary
    with open(os.path.join(out_dir, "summary.md"), "w") as f:
        f.write("# nano-analyzer scan results\n\n")
        f.write(f"- **Target**: `{os.path.abspath(args.path)}`\n")
        f.write(f"- **Date**: {timestamp}\n")
        f.write(f"- **Model**: {args.model}\n")
        f.write(
            f"- **Files scanned**: {len(results)} ({total_lines:,} lines)\n")
        f.write(f"- **Wall time**: {wall_time:.0f}s\n\n")
        f.write("| File | Lines | Critical | High | Medium | Low |\n")
        f.write("|------|-------|----------|------|--------|-----|\n")
        for r in results:
            s = r["severities"]
            f.write(
                f"| {r['display_name']} | {r.get('lines', 0)} "
                f"| {s.get('critical', 0)} | {s.get('high', 0)} "
                f"| {s.get('medium', 0)} | {s.get('low', 0)} |\n"
            )

    print()
