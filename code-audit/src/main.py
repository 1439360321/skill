"""VulnRAG-Audit: LLM-based Code Security Auditor with RAG Enhancement.

Upgraded version with:
- Source→Sink data-flow analysis
- Three-stage LLM pipeline (Triage → Deep Analysis → Self-verification)
- RAG with BigVul real case knowledge base
- Ablation study framework
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from src.config import Config
from src.utils.logger import setup_logger
from src.utils.file_utils import find_source_files
from src.scanner.code_slicer import CodeSlicer
from src.scanner.sca_scanner import SCAScanner
from src.llm.ollama_client import OllamaClient
from shared.llm.openai_client import create_llm_client
from src.llm.stages import StageRunner
from src.llm.parser import LLMOutputParser
from src.postprocess.validator import ResultValidator
from src.postprocess.cwe_mapper import CWEMapper
from src.evaluation.report_generator import ReportGenerator
from src.evaluation.evaluator import Evaluator
from src.evaluation.visualize import Visualizer
from src.utils.cache import CacheManager

logger = setup_logger()


# ---------------------------------------------------------------------------
# Core scan pipeline
# ---------------------------------------------------------------------------


def scan_dependencies(project_path: str) -> list:
    """Run SCA dependency scanning."""
    scanner = SCAScanner()
    return scanner.scan(project_path)


def scan_source_code(
    project_path: str,
    mode: str = "baseline",
    enable_multistage: bool = True,
) -> list:
    """Scan source code for vulnerabilities with the full pipeline."""
    config = Config()
    languages = config.scanner.get("supported_languages", ["c", "python"])
    source_files = list(find_source_files(project_path, languages))
    logger.info(f"Found {len(source_files)} source files in {project_path}")

    slicer = CodeSlicer()
    llm_config = config._data.get("llm", config._data.get("ollama", {}))
    client = create_llm_client(llm_config)
    cache = CacheManager()
    validator = ResultValidator()
    cwe_mapper = CWEMapper()

    if not client.check_health():
        logger.error("Ollama is not running or model not available.")
        logger.error("  Start: ollama serve")
        logger.error(
            f"  Pull model: ollama pull {config.ollama.get('model', 'deepseek-coder-v2:16b')}"
        )
        sys.exit(1)

    # RAG initialisation
    stage_runner = StageRunner(mode=mode, enable_multistage=enable_multistage)
    if mode == "rag":
        from src.rag.knowledge_base import KnowledgeBase

        kb = KnowledgeBase()
        if not kb.is_initialized():
            logger.info("Initializing knowledge base (CWE data)...")
            kb.initialize()

    results: list[dict] = []
    total_slices = 0
    for file_path in source_files:
        code = file_path.read_text(encoding="utf-8-sig", errors="ignore")
        lang = _detect_lang(file_path)
        if not lang:
            continue

        slices = slicer.slice_code(code, lang)
        if not slices:
            continue
        total_slices += len(slices)
        logger.info(f"  [{file_path.name}] {len(slices)} suspicious slice(s)")

        for slc in slices:
            slc["file"] = str(file_path)

            # Cache check
            cache_key = f"{slc['code'][:200]}_{slc['sink_type']}_{mode}_{lang}"
            cached = cache.get(cache_key)
            if cached:
                logger.debug(f"    [{slc['function_name']}] Cache hit")
                cached["file"] = str(file_path)
                cached["function_name"] = slc["function_name"]
                cached["line_start"] = slc["line_start"]
                cached["line_end"] = slc["line_end"]
                cached["language"] = lang
                cached["mode"] = mode
                results.append(cached)
                continue

            # Run multi-stage pipeline
            try:
                parsed = stage_runner.run(slc)

                if parsed is None:
                    # Stage 1 filtered it out — record as safe
                    results.append(
                        {
                            "file": str(file_path),
                            "function_name": slc["function_name"],
                            "line_start": slc["line_start"],
                            "line_end": slc["line_end"],
                            "language": lang,
                            "mode": mode,
                            "sink_type": slc.get("sink_type", ""),
                            "has_vulnerability": False,
                            "vulnerability_type": "NONE",
                            "confidence": 0.0,
                            "description": "Filtered by Stage 1 triage",
                            "status": "SAFE",
                        }
                    )
                    continue

                # CWE mapping
                cwe_id, cwe_conf = CWEMapper.map_to_cwe(
                    parsed.get("vulnerability_type", "UNKNOWN")
                )
                if (
                    parsed.get("vulnerability_type") == "UNKNOWN"
                    or not str(parsed.get("vulnerability_type", "")).startswith("CWE-")
                ):
                    parsed["vulnerability_type"] = cwe_id

                # Validate
                validated = validator.validate_results([parsed])[0]

                # Cache
                cache.set(cache_key, validated)
                results.append(validated)

                status = validated.get("status", validated.get("has_vulnerability", False))
                conf = validated.get("confidence", 0)
                vtype = validated.get("vulnerability_type", "")
                logger.info(
                    f"    [{slc['function_name']}] {status}: {vtype} (conf={conf:.2f})"
                )
            except Exception as e:
                logger.error(f"    [ERROR] {slc['function_name']}: {e}")

    logger.info(f"Scan complete: {total_slices} slices, {len(results)} results")
    return results


def run_evaluation(
    project_path: str,
    ground_truth_path: str,
    enable_multistage: bool = True,
) -> None:
    """Run baseline vs RAG comparison evaluation."""
    logger.info("=== Running BASELINE scan ===")
    baseline = scan_source_code(project_path, mode="baseline", enable_multistage=False)

    logger.info("=== Running RAG scan ===")
    rag = scan_source_code(project_path, mode="rag", enable_multistage=enable_multistage)

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt = json.load(f)

    ev = Evaluator(gt)
    baseline_metrics = ev.evaluate(baseline)
    rag_metrics = ev.evaluate(rag)

    # Print comparison table
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(
            title="Evaluation: Baseline vs RAG",
            box=None,
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Metric", style="bold", justify="center")
        table.add_column("Baseline", style="yellow", justify="center")
        table.add_column("RAG", style="green", justify="center")
        table.add_column("Delta", style="cyan", justify="center")
        for metric in ["Precision", "Recall", "F1", "FPR"]:
            b = baseline_metrics.get(metric, 0)
            r = rag_metrics.get(metric, 0)
            delta = r - b
            sign = "+" if delta > 0 else ""
            table.add_row(metric, f"{b:.4f}", f"{r:.4f}", f"{sign}{delta:.4f}")
        console.print(table)
    except ImportError:
        for m in ["Precision", "Recall", "F1", "FPR"]:
            print(f"  {m}: Baseline={baseline_metrics.get(m,0):.4f}  "
                  f"RAG={rag_metrics.get(m,0):.4f}")

    # Save metrics
    config = Config()
    output_dir = config.evaluation.get("output_dir", "./reports")
    viz = Visualizer(output_dir)
    chart_path = viz.plot_comparison(baseline_metrics, rag_metrics)
    if chart_path:
        console.print(f"\n[green]Chart saved to {chart_path}[/green]")

    metrics_path = Path(output_dir) / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump({"baseline": baseline_metrics, "rag": rag_metrics}, f, indent=2)
    console.print(f"[green]Metrics saved to {metrics_path}[/green]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VulnRAG-Audit: LLM + RAG Code Security Auditor (Upgraded)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.main ./project --mode baseline
  python -m src.main ./project --mode rag --json -o ./reports
  python -m src.main ./project --mode rag --json --sca
  python -m src.main ./project --evaluate --ground-truth ./data/ground_truth.json
        """,
    )
    parser.add_argument(
        "project",
        help="Path to the project directory to scan",
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "rag"],
        default="baseline",
        help="Scan mode (default: baseline)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./reports",
        help="Output directory (default: ./reports)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON report",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Output HTML report",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Also run SCA dependency scan",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Run baseline vs RAG comparison",
    )
    parser.add_argument(
        "--ground-truth",
        help="Path to ground truth JSON for evaluation",
    )
    parser.add_argument(
        "--no-multistage",
        action="store_true",
        help="Disable multi-stage inference",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        setup_logger("vulnrag", logging.DEBUG)

    project_path = Path(args.project)
    if not project_path.exists():
        logger.error(f"Path not found: {project_path}")
        sys.exit(1)

    # Evaluation mode
    if args.evaluate:
        gt_path = args.ground_truth
        if not gt_path:
            logger.error("--ground-truth required for evaluation mode")
            sys.exit(1)
        run_evaluation(
            str(project_path),
            gt_path,
            enable_multistage=not args.no_multistage,
        )
        return

    # SCA scan
    sca_results: list = []
    if args.sca:
        logger.info("[SCA] Scanning dependencies...")
        sca_results = scan_dependencies(str(project_path))

    # Source code scan
    logger.info(f"[{args.mode.upper()}] Scanning source code...")
    results = scan_source_code(
        str(project_path),
        mode=args.mode,
        enable_multistage=not args.no_multistage,
    )

    # Reports
    reporter = ReportGenerator(output_dir=args.output)
    reporter.generate_cli_report(results, mode=args.mode)

    if sca_results:
        try:
            from rich.console import Console
            from rich.table import Table

            console = Console()
            console.print("\n[bold red]Dependency Vulnerabilities (SCA)[/bold red]")
            sca_table = Table(box=None, show_header=True, header_style="bold red")
            sca_table.add_column("Package", style="cyan")
            sca_table.add_column("Version", style="yellow")
            sca_table.add_column("CVE", style="red")
            sca_table.add_column("Severity", style="magenta")
            sca_table.add_column("Fixed", style="green")
            sca_table.add_column("Summary", style="white", max_width=40)
            for v in sca_results:
                sca_table.add_row(
                    v["package"],
                    v["version"],
                    v["cve_id"],
                    v["severity"],
                    v.get("fixed_version", ""),
                    v.get("summary", "")[:40],
                )
            console.print(sca_table)
        except ImportError:
            for v in sca_results:
                print(f"  [{v['severity']}] {v['package']} {v['version']}: {v['cve_id']}")

    if args.json:
        reporter.generate_json_report(results, sca_results=sca_results)
    if args.html:
        reporter.generate_html_report(results, sca_results=sca_results)

    logger.info("Done!")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_lang(file_path: Path) -> str | None:
    ext = file_path.suffix.lower()
    if ext in (".c", ".h"):
        return "c"
    if ext == ".py":
        return "python"
    if ext == ".java":
        return "java"
    return None


if __name__ == "__main__":
    main()
