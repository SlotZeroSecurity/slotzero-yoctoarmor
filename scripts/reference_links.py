"""Check local reference destinations and Markdown heading anchors without writes."""
from __future__ import annotations

from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote


def heading_anchors(text: str) -> set[str]:
    anchors = set(re.findall(r'<a\s+(?:name|id)=["\']([^"\']+)["\']', text))
    occurrences: dict[str, int] = {}
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence:
            continue
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*$", line)
        if not match:
            continue
        title = re.sub(r"<[^>]+>", "", match[1]).lower()
        slug = "".join(c for c in title if c in "-_ " or unicodedata.category(c)[0] in "LN")
        slug = slug.replace(" ", "-")
        occurrence = occurrences.get(slug, 0)
        occurrences[slug] = occurrence + 1
        anchors.add(slug + (f"-{occurrence}" if occurrence else ""))
    return anchors


def reference_link_errors(root: Path) -> list[str]:
    errors = []
    cache: dict[Path, set[str]] = {}
    for path in [root / "README.md", root / "SKILL.md", *sorted((root / "references").rglob("*.md"))]:
        if not path.is_file():
            errors.append(f"missing document: {path.relative_to(root)}")
            continue
        for destination in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in destination:
                continue
            relative, separator, fragment = destination.partition("#")
            target = (path.parent / unquote(relative)).resolve() if relative else path.resolve()
            if not target.is_file():
                errors.append(f"broken link in {path.relative_to(root)}: {destination}")
            elif separator and target.suffix == ".md":
                if target not in cache:
                    cache[target] = heading_anchors(target.read_text(encoding="utf-8"))
                if unquote(fragment) not in cache[target]:
                    errors.append(f"broken anchor in {path.relative_to(root)}: {destination}")
    return errors
