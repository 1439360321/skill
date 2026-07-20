"""File system utilities for finding source files."""

from pathlib import Path
from typing import Iterator


EXTENSION_MAP = {
    "c": [".c", ".h"],
    "python": [".py"],
    "java": [".java"],
}


def find_source_files(
    project_path: str,
    languages: list[str] | None = None,
) -> Iterator[Path]:
    """Yield Path objects for source files in the given project directory.

    Args:
        project_path: Root directory to scan.
        languages: List of language names (e.g. ``["c", "python"]``).
                   When None, all supported languages are used.
    """
    root = Path(project_path)

    if languages is None:
        languages = list(EXTENSION_MAP.keys())

    extensions: set[str] = set()
    for lang in languages:
        extensions.update(EXTENSION_MAP.get(lang, []))

    for ext in extensions:
        yield from root.rglob(f"*{ext}")


def detect_language(file_path: Path) -> str | None:
    """Return the language name for a source file, or None if unsupported."""
    suffix = file_path.suffix.lower()
    if suffix in (".c", ".h"):
        return "c"
    if suffix == ".py":
        return "python"
    if suffix == ".java":
        return "java"
    return None
