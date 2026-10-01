# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

DEFAULT_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
    ".java", ".py", ".go", ".rs", ".js", ".ts", ".rb",
    ".swift", ".m", ".mm", ".cs", ".php", ".pl", ".sh",
    ".x",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
    "clean": "🟢",
}

VERDICT_EMOJI = {
    "VALID": "✅",
    "INVALID": "❌",
    "UNCERTAIN": "❓",
    "ERROR": "💥",
}

MAX_GREP_REQUESTS = 3
MAX_GREP_LINES = 30
MAX_GREP_LINE_LEN = 2000
