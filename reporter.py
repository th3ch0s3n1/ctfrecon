from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from models import Target
    from scanner import Scanner


class Reporter:
    def __init__(self, scanner: "Scanner") -> None:
        self.scanner = scanner
        templates_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=False,
        )

    def generate(self, target: "Target") -> None:
        scandir = Path(target.scandir)
        scandir.mkdir(parents=True, exist_ok=True)

        findings = self.scanner.findings.get(target.address, [])
        state = self.scanner.states.get(target.address)
        completed = state.completed_plugins if state else []

        context = {
            "target": target,
            "services": sorted(target.services, key=lambda s: s.port),
            "findings": findings,
            "completed_plugins": completed,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }

        # Markdown report
        md_tmpl = self.env.get_template("report.md.j2")
        md_content = md_tmpl.render(**context)
        (scandir / "report.md").write_text(md_content, encoding="utf-8")

        # HTML report
        html_tmpl = self.env.get_template("report.html.j2")
        html_content = html_tmpl.render(**context)
        (scandir / "report.html").write_text(html_content, encoding="utf-8")
