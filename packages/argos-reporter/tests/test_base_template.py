"""The base layout compiles, renders and hardens the HTML report."""

from __future__ import annotations

import pytest
from argos_reporter.html import build_env


@pytest.fixture
def rendered_base() -> str:
    env = build_env()
    return env.get_template("base.html.j2").render(
        generator_version="0.0.1",
        generated_at="2026-04-15T00:00:00Z",
    )


def test_base_template_renders(rendered_base: str) -> None:
    assert "<!doctype html>" in rendered_base
    assert "ARGOS" in rendered_base
    assert "AGPL-3.0-or-later" in rendered_base
    assert "--argos-color-green-600" in rendered_base


def test_base_template_autoescapes_html() -> None:
    env = build_env()
    rendered = env.from_string("{{ value }}").render(value="<script>alert(1)</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_base_template_ships_strict_csp(rendered_base: str) -> None:
    assert "Content-Security-Policy" in rendered_base
    assert "default-src 'none'" in rendered_base
    assert "frame-ancestors 'none'" in rendered_base
    assert "base-uri 'none'" in rendered_base


def test_base_template_disables_content_sniffing(rendered_base: str) -> None:
    assert 'X-Content-Type-Options" content="nosniff"' in rendered_base


def test_base_template_blocks_referrer_leak(rendered_base: str) -> None:
    assert 'name="referrer" content="no-referrer"' in rendered_base


def test_base_template_advertises_no_index(rendered_base: str) -> None:
    assert 'name="robots" content="noindex, nofollow"' in rendered_base
