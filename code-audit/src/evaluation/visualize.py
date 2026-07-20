"""Visualization helpers — comparison charts and metrics plots."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class Visualizer:
    """Generate comparison charts and visual reports."""

    def __init__(self, output_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def plot_comparison(
        self,
        baseline_metrics: dict[str, float],
        rag_metrics: dict[str, float],
        filename: str = "comparison.png",
    ) -> str:
        """Generate a bar chart comparing baseline vs RAG metrics."""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            return "matplotlib not available"

        metrics = ["Precision", "Recall", "F1", "FPR"]
        baseline_vals = [baseline_metrics.get(m, 0) for m in metrics]
        rag_vals = [rag_metrics.get(m, 0) for m in metrics]

        x = range(len(metrics))
        width = 0.35

        fig, ax = plt.subplots(figsize=(10, 6))
        bars1 = ax.bar([i - width / 2 for i in x], baseline_vals, width, label="Baseline")
        bars2 = ax.bar([i + width / 2 for i in x], rag_vals, width, label="RAG")

        ax.set_ylabel("Score")
        ax.set_title("Baseline vs RAG-Enhanced Vulnerability Detection")
        ax.set_xticks(x)
        ax.set_xticklabels(metrics)
        ax.legend()
        ax.set_ylim(0, 1)
        ax.grid(axis="y", alpha=0.3)

        # Value labels on bars
        for bar in bars1:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01, f"{h:.3f}",
                    ha="center", va="bottom", fontsize=8)
        for bar in bars2:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.01, f"{h:.3f}",
                    ha="center", va="bottom", fontsize=8)

        out_path = self.output_dir / filename
        fig.savefig(out_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return str(out_path)

    def plot_ablation(
        self,
        results: dict[str, dict[str, float]],
        filename: str = "ablation.png",
    ) -> str:
        """Generate an ablation study bar chart."""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            return "matplotlib not available"

        configs = list(results.keys())
        metrics = ["Precision", "Recall", "F1"]

        fig, ax = plt.subplots(figsize=(12, 6))
        x = range(len(configs))
        width = 0.25

        colors = ["#2196F3", "#4CAF50", "#FF9800"]
        for i, metric in enumerate(metrics):
            vals = [results[c].get(metric, 0) for c in configs]
            bars = ax.bar(
                [xi + (i - 1) * width for xi in x],
                vals,
                width,
                label=metric,
                color=colors[i],
            )
            for bar in bars:
                h = bar.get_height()
                ax.text(
                    bar.get_x() + bar.get_width() / 2, h + 0.01,
                    f"{h:.3f}", ha="center", va="bottom", fontsize=7,
                )

        ax.set_ylabel("Score")
        ax.set_title("Ablation Study — Incremental Improvement")
        ax.set_xticks(x)
        ax.set_xticklabels(configs, fontsize=9)
        ax.legend()
        ax.set_ylim(0, 1)
        ax.grid(axis="y", alpha=0.3)

        out_path = self.output_dir / filename
        fig.savefig(out_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return str(out_path)
