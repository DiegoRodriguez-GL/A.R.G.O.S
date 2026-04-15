"""The base layout compiles and renders without runtime errors."""

from __future__ import annotations


def test_base_template_renders() -> None:
    from argos_reporter.html import build_env

    env = build_env()
    template = env.get_template("base.html.j2")
    html = template.render(
        generator_version="0.0.1",
        generated_at="2026-04-15T00:00:00Z",
    )
    assert "<!doctype html>" in html
    assert "ARGOS" in html
    assert "AGPL-3.0-or-later" in html
    assert "--argos-color-green-600" in html
    assert "role=" not in html  # no stray attributes; base is intentionally plain


def test_base_template_autoescapes_html() -> None:
    from argos_reporter.html import build_env

    env = build_env()
    template = env.from_string("{{ value }}")
    rendered = template.render(value="<script>alert(1)</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
