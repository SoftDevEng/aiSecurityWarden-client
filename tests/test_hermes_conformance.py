"""Hermes Agent's own secret-source conformance kit, run against the aiSecurityWarden plugin.

Skipped unless a Hermes Agent checkout is importable (the `Hermes compatibility` workflow puts one on PYTHONPATH,
pinned and latest). Locally: `PYTHONPATH=/path/to/hermes-agent pytest tests/test_hermes_conformance.py`.
"""

import pytest

conformance = pytest.importorskip("tests.secret_sources.conformance",
                                  reason="needs a Hermes Agent checkout on PYTHONPATH")

from securitywarden.hermes_plugin import AiSecurityWardenSource  # noqa: E402


class TestAiSecurityWardenConformance(conformance.SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return AiSecurityWardenSource()
