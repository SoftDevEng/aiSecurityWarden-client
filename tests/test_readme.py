"""The README is also the PyPI page, where relative links break (they resolve against pypi.org). Keep them absolute."""

import pathlib
import re

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"


def test_readme_links_are_absolute():
    text = README.read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:src|href)="([^"]+)"', text)
    relative = [u for u in links if not re.match(r"(https?://|mailto:|#)", u)]
    assert not relative, f"use full GitHub URLs in README.md (it is the PyPI page too): {relative}"


def test_mcp_registry_entry_matches_the_package():
    """server.json (the official MCP Registry entry) must name the same server as the README's mcp-name line (the
    registry's ownership check) and the version being released."""
    import json
    from securitywarden import __version__
    server = json.loads((README.parent / "server.json").read_text(encoding="utf-8"))
    assert f"<!-- mcp-name: {server['name']} -->" in README.read_text(encoding="utf-8")
    assert server["version"] == __version__
    [pkg] = server["packages"]
    assert pkg["registryType"] == "pypi" and pkg["identifier"] == "aisecuritywarden" and pkg["version"] == __version__
    assert len(server["description"]) <= 100
