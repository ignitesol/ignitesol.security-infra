"""Jinja2 HTML + plaintext email rendering."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Two levels up from secinfra/common/render.py → secinfra/ → templates/
# Works both in development and after pip install.
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(template_name: str, **context) -> str:
    return _env().get_template(f"{template_name}.html.j2").render(**context)


def render_text(template_name: str, **context) -> str:
    return _env().get_template(f"{template_name}.txt.j2").render(**context)
