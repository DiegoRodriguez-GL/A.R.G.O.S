"""Deep audit of the reporter surface: env safety, CSP and rendering invariants."""

from __future__ import annotations

import pytest
from argos_reporter.html import build_env, static_path, templates_path
from jinja2 import UndefinedError


def test_paths_exist_on_disk() -> None:
    assert templates_path().is_dir()
    assert static_path().is_dir()


def test_env_rejects_undefined_variables() -> None:
    # StrictUndefined: referring to an undeclared variable must raise at render time.
    env = build_env()
    with pytest.raises(UndefinedError):
        env.from_string("{{ missing_value }}").render()


def test_env_escapes_html_in_string_mode() -> None:
    env = build_env()
    # default_for_string=True in autoescape config.
    rendered = env.from_string("{{ body }}").render(body="<script>bad()</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_base_template_blocks_form_action() -> None:
    env = build_env()
    html = env.get_template("base.html.j2").render(
        generator_version="0.0.1",
        generated_at="now",
    )
    assert "form-action 'none'" in html


def test_base_template_keeps_trailing_newline() -> None:
    env = build_env()
    html = env.get_template("base.html.j2").render(
        generator_version="0.0.1",
        generated_at="now",
    )
    assert html.endswith("\n")


def test_base_template_lang_defaults_to_english() -> None:
    env = build_env()
    html = env.get_template("base.html.j2").render(
        generator_version="0.0.1",
        generated_at="now",
    )
    assert 'lang="en"' in html


def test_base_template_accepts_spanish_lang() -> None:
    env = build_env()
    html = env.get_template("base.html.j2").render(
        generator_version="0.0.1",
        generated_at="now",
        lang="es",
    )
    assert 'lang="es"' in html


def test_static_dir_contains_placeholder_assets() -> None:
    # Ensure the static asset expected by M6 is present so the wheel packages it.
    assert (static_path() / "argos.css").is_file()
    assert (static_path() / "argos.js").is_file()
