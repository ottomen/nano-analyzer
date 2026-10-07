import os


def discover_files(path, extensions, max_chars):
    """Walk a path (file or dir) and return (scannable, skipped) lists."""
    scannable = []
    skipped = []

    if os.path.isfile(path):
        candidates = [path]
    else:
        candidates = []
        for root, _, fnames in os.walk(path):
            for fn in sorted(fnames):
                candidates.append(os.path.join(root, fn))

    for filepath in candidates:
        if os.path.islink(filepath):
            skipped.append((filepath, "symlink"))
            continue

        ext = os.path.splitext(filepath)[1].lower()
        if extensions and ext not in extensions:
            skipped.append((filepath, "extension"))
            continue

        try:
            size = os.path.getsize(filepath)
        except OSError:
            skipped.append((filepath, "unreadable"))
            continue

        if size > max_chars:
            skipped.append((filepath, f"too large ({size:,} bytes)"))
            continue

        try:
            with open(filepath) as f:
                content = f.read()
            line_count = content.count("\n")
            char_count = len(content)
        except (OSError, UnicodeDecodeError):
            skipped.append((filepath, "unreadable/binary"))
            continue

        if char_count > max_chars:
            skipped.append((filepath, f"too large ({char_count:,} chars)"))
            continue

        scannable.append(
            {
                "filepath": filepath,
                "lines": line_count,
                "chars": char_count,
            }
        )

    return scannable, skipped
