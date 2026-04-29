"""Reporting engine. Jinja2 base layout + design-system tokens.

Public API: :func:`render_html` turns a :class:`argos_core.ScanResult`
into a self-contained HTML document. The document is offline-safe, has
a strict Content-Security-Policy and follows the Greenlock-aligned
ARGOS design language (dark cover header, emerald accent, severity
colour-coded cards).
"""

from __future__ import annotations

from argos_reporter.render import render_html
from argos_reporter.render_eval import render_eval_html

__all__ = ["render_eval_html", "render_html"]

__version__ = "0.0.1"
