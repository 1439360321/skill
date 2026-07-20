"""Report generator — CLI tables, JSON, and HTML reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()


class ReportGenerator:
    """Generate vulnerability audit reports in multiple formats."""

    def __init__(self, output_dir: str = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_cli_report(
        self,
        results: list[dict[str, Any]],
        mode: str = "baseline",
    ) -> None:
        """Print a formatted table to the terminal."""
        try:
            from rich.console import Console
            from rich.table import Table
        except ImportError:
            self._plain_cli_report(results, mode)
            return

        console = Console()

        vulns = [r for r in results if r.get("has_vulnerability")]
        console.print(
            f"\n[bold]Scan Results ([cyan]{mode.upper()}[/cyan] mode)[/bold]"
        )
        console.print(
            f"Total: {len(results)} slices | "
            f"[red]Vulnerabilities: {len(vulns)}[/red]"
        )

        if not vulns:
            console.print("[green]No vulnerabilities found.[/green]")
            return

        table = Table(box=None, show_header=True, header_style="bold magenta")
        table.add_column("Function", style="cyan", max_width=25)
        table.add_column("Vulnerability", style="red", max_width=20)
        table.add_column("Conf", style="yellow", justify="center")
        table.add_column("Severity", style="bold", justify="center")
        table.add_column("Sink", style="dim", max_width=15)
        table.add_column("Description", style="white", max_width=40)

        for v in vulns[:30]:
            table.add_row(
                v.get("function_name", "?")[:25],
                v.get("vulnerability_type", "?")[:20],
                f"{v.get('confidence', 0):.2f}",
                v.get("severity", "?"),
                v.get("sink_type", "?")[:15],
                v.get("description", "")[:40],
            )

        console.print(table)
        if len(vulns) > 30:
            console.print(f"  ... and {len(vulns) - 30} more")

    def _plain_cli_report(self, results: list[dict], mode: str) -> None:
        vulns = [r for r in results if r.get("has_vulnerability")]
        print(f"\nScan Results ({mode.upper()} mode)")
        print(f"Total: {len(results)} | Vulnerabilities: {len(vulns)}")
        for v in vulns[:20]:
            print(
                f"  [{v.get('severity', '?')}] {v.get('function_name', '?')}: "
                f"{v.get('vulnerability_type', '?')} (conf={v.get('confidence', 0):.2f})"
            )

    def generate_json_report(
        self,
        results: list[dict[str, Any]],
        path: str | None = None,
        sca_results: list[dict] | None = None,
    ) -> str:
        """Write a JSON report and return the file path."""
        if path is None:
            path = str(self.output_dir / "report.json")

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_slices": len(results),
            "vulnerabilities_found": len(
                [r for r in results if r.get("has_vulnerability")]
            ),
            "results": results,
        }
        if sca_results:
            report_data["dependency_vulnerabilities"] = sca_results

        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report_data, indent=2, ensure_ascii=False))
        logger.info(f"JSON report saved to {output}")
        return str(output)

    def generate_html_report(
        self,
        results: list[dict[str, Any]],
        sca_results: list[dict] | None = None,
        path: str | None = None,
    ) -> str:
        """Generate a self-contained HTML report."""
        if path is None:
            path = str(self.output_dir / "report.html")

        vulns = [r for r in results if r.get("has_vulnerability")]
        safe = len(results) - len(vulns)

        severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnRAG-Audit — Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; background: #f5f5f5; }}
  .card {{ background: white; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .stat {{ flex: 1; min-width: 120px; text-align: center; padding: 1rem; background: #e3f2fd; border-radius: 8px; }}
  .stat.high {{ background: #ffebee; }}
  .stat.medium {{ background: #fff3e0; }}
  .stat.low {{ background: #e8f5e9; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  th {{ background: #fafafa; font-weight: 600; }}
  pre {{ background: #263238; color: #aed581; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
  .severity-HIGH {{ color: #c62828; font-weight: bold; }}
  .severity-MEDIUM {{ color: #ef6c00; font-weight: bold; }}
  .severity-LOW {{ color: #2e7d32; }}
</style>
</head>
<body>
<h1>🔒 VulnRAG-Audit — Security Report</h1>
<p><em>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>

<div class="summary">
  <div class="stat"><strong>{len(vulns)}</strong><br>Vulnerabilities</div>
  <div class="stat"><strong>{safe}</strong><br>Safe Slices</div>
  <div class="stat high"><strong>{severity_count.get('HIGH', 0)}</strong><br>HIGH</div>
  <div class="stat medium"><strong>{severity_count.get('MEDIUM', 0)}</strong><br>MEDIUM</div>
  <div class="stat low"><strong>{severity_count.get('LOW', 0) + severity_count.get('INFO', 0)}</strong><br>LOW/INFO</div>
</div>
"""
        if sca_results:
            html += f"""<div class="card">
<h2>Dependency Vulnerabilities (SCA)</h2>
<table><tr><th>Package</th><th>Version</th><th>CVE</th><th>Severity</th><th>Summary</th></tr>
"""
            for s in sca_results:
                html += f"<tr><td>{s['package']}</td><td>{s['version']}</td><td>{s['cve_id']}</td><td>{s['severity']}</td><td>{s.get('summary', '')[:80]}</td></tr>"
            html += "</table></div>"

        html += """<div class="card"><h2>Source Code Vulnerabilities</h2><table>
<tr><th>File</th><th>Function</th><th>Type</th><th>Conf</th><th>Severity</th><th>Sink</th></tr>
"""
        for v in sorted(vulns, key=lambda x: x.get("confidence", 0), reverse=True):
            sev = v.get("severity", "INFO")
            html += (
                f"<tr>"
                f"<td>{v.get('file', '?')[-40:]}</td>"
                f"<td>{v.get('function_name', '?')[:30]}</td>"
                f"<td>{v.get('vulnerability_type', '?')}</td>"
                f"<td>{v.get('confidence', 0):.2f}</td>"
                f"<td class=\"severity-{sev}\">{sev}</td>"
                f"<td>{v.get('sink_type', '?')}</td>"
                f"</tr>"
            )
        html += "</table></div>"

        html += "</body></html>"
        out = Path(path)
        out.write_text(html, encoding="utf-8")
        logger.info(f"HTML report saved to {out}")
        return str(out)
