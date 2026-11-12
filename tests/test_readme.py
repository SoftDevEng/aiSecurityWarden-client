"""The README is also the PyPI page, where relative links break (they resolve against pypi.org). Keep them absolute."""

import pathlib
import re

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


def test_readme_links_are_absolute():
    text = README.read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:src|href)="([^"]+)"', text)
    relative = [u for u in links if not re.match(r"(https?://|mailto:|#)", u)]
    assert not relative, f"use full GitHub URLs in README.md (it is the PyPI page too): {relative}"
