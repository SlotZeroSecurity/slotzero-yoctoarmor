"""Shared, read-only policy checks for the distributed skill package."""
from pathlib import Path
import re


def external_url_paths(root: Path) -> list[str]:
    """Find prohibited URLs; only the top-level README may contain web links."""
    contaminated = []
    for path in sorted(root.rglob("*")):
        if path == root / "README.md":
            continue
        if path.is_file() and path.suffix in {".md", ".json", ".py", ".rs", ".yaml"}:
            if re.search(r"https?://", path.read_text(encoding="utf-8", errors="replace")):
                contaminated.append(path.relative_to(root).as_posix())
    return contaminated
