"""Evaluation engine — calculates Precision/Recall/F1/FPR and produces
comparative reports (baseline vs RAG vs multi-stage).
"""

from __future__ import annotations

from typing import Any


class Evaluator:
    """Evaluate vulnerability detection against ground truth."""

    def __init__(self, ground_truth: list[dict[str, Any]]) -> None:
        self.ground_truth = ground_truth

    def evaluate(self, predictions: list[dict[str, Any]]) -> dict[str, float]:
        """Calculate TP/FP/FN/TN and derived metrics.

        Matching is done on (file_basename, function_name) only —
        CWE IDs vary in format across sources so we don't key on them.
        """
        tp = fp = fn = tn = 0

        # Build lookup — key = (basename, function_name)
        gt_dict: dict[tuple, bool] = {}
        for gt in self.ground_truth:
            file = self._normalize_path(gt.get("file", ""))
            key = (file, gt.get("function_name", ""))
            gt_dict[key] = gt.get("has_vulnerability", False)

        pred_dict: dict[tuple, bool] = {}
        for pred in predictions:
            file = self._normalize_path(pred.get("file", ""))
            key = (file, pred.get("function_name", ""))
            pred_dict[key] = pred.get("has_vulnerability", False)

        all_keys = set(gt_dict.keys()) | set(pred_dict.keys())
        for key in all_keys:
            gt_vuln = gt_dict.get(key, False)
            pred_vuln = pred_dict.get(key, False)
            if gt_vuln and pred_vuln:
                tp += 1
            elif not gt_vuln and pred_vuln:
                fp += 1
            elif gt_vuln and not pred_vuln:
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "Precision": round(precision, 4),
            "Recall": round(recall, 4),
            "F1": round(f1, 4),
            "FPR": round(fpr, 4),
        }

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a file path to its basename for cross-platform matching."""
        import os
        return os.path.basename(path.replace("\\", "/"))

    def print_results(self, results: dict[str, float]) -> None:
        """Pretty-print evaluation results via Rich."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box

            console = Console()
            table = Table(title="Evaluation Results", box=box.ROUNDED)
            table.add_column("Metric", style="bold")
            table.add_column("Value", style="cyan")
            for metric in [
                "Precision", "Recall", "F1", "FPR",
                "TP", "FP", "FN", "TN",
            ]:
                table.add_row(metric, str(results.get(metric, 0)))
            console.print(table)
        except ImportError:
            for k, v in results.items():
                print(f"  {k}: {v}")
