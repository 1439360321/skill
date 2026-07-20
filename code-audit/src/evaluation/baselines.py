"""Run external SAST baselines (CodeQL, Semgrep, Bandit) and parse their
output for comparison with VulnRAG-Audit.

Each tool is executed as a subprocess; results are normalised into the
shared evaluation format.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()


class BaselineRunner:
    """Run external tools and collect results."""

    @staticmethod
    def run_semgrep(project_path: str, languages: list[str] | None = None) -> list[dict]:
        """Run Semgrep and return normalised findings."""
        cmd = ["semgrep", "--config=auto", "--json", "--quiet", project_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode not in (0, 1):  # 1 = findings found
                logger.warning(f"Semgrep returned {result.returncode}")
            data = json.loads(result.stdout)
            findings: list[dict] = []
            for r in data.get("results", []):
                findings.append(
                    {
                        "tool": "semgrep",
                        "file": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "rule": r.get("check_id", ""),
                        "message": r.get("extra", {}).get("message", ""),
                        "severity": r.get("extra", {}).get("severity", "WARNING"),
                    }
                )
            return findings
        except FileNotFoundError:
            logger.warning("Semgrep not installed — skipping")
            return []
        except Exception as e:
            logger.error(f"Semgrep failed: {e}")
            return []

    @staticmethod
    def run_bandit(project_path: str) -> list[dict]:
        """Run Bandit on Python code and return normalised findings."""
        cmd = ["bandit", "-r", "-f", "json", project_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            data = json.loads(result.stdout)
            findings: list[dict] = []
            for r in data.get("results", []):
                findings.append(
                    {
                        "tool": "bandit",
                        "file": r.get("filename", ""),
                        "line": r.get("line_number", 0),
                        "rule": r.get("test_id", ""),
                        "message": r.get("issue_text", ""),
                        "severity": r.get("issue_severity", "medium"),
                        "confidence": r.get("issue_confidence", "medium"),
                    }
                )
            return findings
        except FileNotFoundError:
            logger.warning("Bandit not installed — skipping")
            return []
        except Exception as e:
            logger.error(f"Bandit failed: {e}")
            return []

    @staticmethod
    def run_all(project_path: str) -> dict[str, list[dict]]:
        """Run all available baselines and return a dict keyed by tool name."""
        return {
            "semgrep": BaselineRunner.run_semgrep(project_path),
            "bandit": BaselineRunner.run_bandit(project_path),
        }
