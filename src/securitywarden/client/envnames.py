"""Environment variable names a secret must not set without the owner saying so.

A secret named ``LD_PRELOAD`` would make every program it reaches load a library of the vault's choosing; ``PATH``,
``PYTHONPATH`` or ``NODE_OPTIONS`` change which code runs; ``HTTPS_PROXY`` or ``SSL_CERT_FILE`` change where traffic
goes and whom it trusts. ``swctl run`` and the Hermes plugin refuse them unless allowed. The Hermes plugin keeps its own
copy of this list (it imports nothing from this package); ``tests/test_hermes_plugin.py`` keeps the two equal.
"""

from __future__ import annotations

DANGEROUS_NAMES = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
    "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",
    "PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    "BASH_ENV", "ENV", "PATH", "PATHEXT", "COMSPEC", "SHELL", "HOME", "USERPROFILE",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH",
})
DANGEROUS_PREFIXES = ("DYLD_",)


def dangerous_name(name: str) -> bool:
    """Whether a name changes how programs load code or connect (compared without case, as Windows does)."""
    up = name.upper()
    return up in DANGEROUS_NAMES or up.startswith(DANGEROUS_PREFIXES)
