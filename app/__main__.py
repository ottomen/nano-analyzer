# Copyright (c) 2026 Aisle Inc.
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys

from .constants import SEVERITY_LEVELS
from .orchestrator import run_scan

model_default = os.getenv("DEFAULT_MODEL")
parallel_default = os.getenv("DEFAULT_PARALLEL")
chars_max = os.getenv("DEFAULT_MAX_CHARS")


def main():
    parser = argparse.ArgumentParser(
        prog="nano-analyzer",
        description="Minimal LLM-powered Electron vulnerability scanner",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--model",
        default=model_default,
        help=f"Model for all stages (default: {model_default})",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=parallel_default,
        help=f"Max concurrent scan calls (default: {parallel_default})",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=chars_max,
        help=f"Skip files larger than this (default: {chars_max})",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: ./analyzer-results/<timestamp>/)",
    )
    parser.add_argument(
        "--triage-threshold",
        default="medium",
        choices=SEVERITY_LEVELS[:4],
        help="Triage findings at or above this severity (default: medium)",
    )
    parser.add_argument(
        "--triage-rounds",
        type=int,
        default=5,
        help="Triage rounds per finding (default: 5)",
    )
    parser.add_argument(
        "--triage-parallel",
        type=int,
        default=50,
        help="Max concurrent triage calls (default: 50)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=None,
        help="Max total concurrent API calls (default: parallel + triage-parallel)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only show findings above this confidence threshold, "
        "e.g. 0.7 for 70%% (default: 0, show all)",
    )
    parser.add_argument(
        "--project",
        default=None,
        help="Project name for triage prompt (default: directory name)",
    )
    parser.add_argument(
        "--repo-dir",
        default=None,
        help="Root of the full repo for triage grep lookups "
        "(default: parent dir for files, scan dir for folders)",
    )
    parser.add_argument(
        "--verbose-triage", action="store_true", help="Show per-round triage progress"
    )
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"❌ Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    run_scan(args)


if __name__ == "__main__":
    main()
