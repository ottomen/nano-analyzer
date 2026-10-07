DEFAULT_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".cjs", ".mjs"}

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
VERSION = "0.1"
