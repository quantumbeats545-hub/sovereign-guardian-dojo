"""Visualization tooling for Guardian Gym training results."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from .analyzer import GuardianAnalyzer


class GuardianVisualizer:
    """Generate plots from Guardian Gym training data."""

    def __init__(self, lineage_path: str = "data/guardian_lineage.json"):
        self.analyzer = GuardianAnalyzer(lineage_path=lineage_path)

    def plot_fitness_trend(self, output: str | None = None) -> None:
        """Plot best and average fitness across generations."""
        df = self.analyzer.fitness_trend()
        if df.empty:
            print("No data to plot.")
            return

        fig, ax1 = plt.subplots(figsize=(10, 6))

        ax1.plot(df["generation"], df["best_fitness"], "b-o", label="Best Fitness", linewidth=2)
        ax1.plot(df["generation"], df["avg_fitness"], "b--s", label="Avg Fitness", alpha=0.7)
        ax1.set_xlabel("Generation")
        ax1.set_ylabel("Fitness", color="b")
        ax1.tick_params(axis="y", labelcolor="b")
        ax1.set_ylim(0, 1.05)

        ax2 = ax1.twinx()
        ax2.plot(df["generation"], df["best_detection_rate"], "g-^", label="Detection Rate", linewidth=2)
        ax2.plot(df["generation"], df["best_fpr"], "r-v", label="False Positive Rate", linewidth=2)
        ax2.set_ylabel("Rate", color="k")
        ax2.set_ylim(0, 1.05)

        # Graduation thresholds
        ax2.axhline(y=0.95, color="g", linestyle=":", alpha=0.5, label="Detection target (95%)")
        ax2.axhline(y=0.05, color="r", linestyle=":", alpha=0.5, label="FPR target (5%)")

        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc="center right")

        plt.title("Guardian Evolution — Fitness Trend")
        plt.tight_layout()

        if output:
            plt.savefig(output, dpi=150)
            print(f"Saved to {output}")
        else:
            plt.show()

    def plot_specialization_heatmap(self, output: str | None = None) -> None:
        """Plot a heatmap of specialization distribution across generations."""
        df = self.analyzer.specialization_breakdown()
        if df.empty:
            print("No data to plot.")
            return

        fig, ax = plt.subplots(figsize=(10, 6))
        im = ax.imshow(df.T.values, aspect="auto", cmap="YlOrRd")

        ax.set_xticks(range(len(df.index)))
        ax.set_xticklabels([f"Gen {g}" for g in df.index])
        ax.set_yticks(range(len(df.columns)))
        ax.set_yticklabels(df.columns)

        for i in range(len(df.columns)):
            for j in range(len(df.index)):
                val = int(df.T.iloc[i, j])
                ax.text(j, i, str(val), ha="center", va="center", color="black" if val < 3 else "white")

        plt.colorbar(im, ax=ax, label="Count")
        plt.title("Guardian Specialization Distribution by Generation")
        plt.xlabel("Generation")
        plt.ylabel("Specialization")
        plt.tight_layout()

        if output:
            plt.savefig(output, dpi=150)
            print(f"Saved to {output}")
        else:
            plt.show()

    def plot_detection_by_scenario(self, output: str | None = None) -> None:
        """Plot detection rates by scenario type (from prompt fitness data)."""
        prompt_df = self.analyzer.prompt_stats()
        if prompt_df.empty:
            print("No data to plot.")
            return

        latest_gen = prompt_df["generation"].max()
        latest = prompt_df[prompt_df["generation"] == latest_gen]

        fig, ax = plt.subplots(figsize=(10, 6))
        specs = latest.groupby("specialization")["detection_rate"].mean().sort_values()
        specs.plot(kind="barh", ax=ax, color="steelblue")
        ax.set_xlabel("Average Detection Rate")
        ax.set_title(f"Detection Rate by Specialization (Gen {int(latest_gen)})")
        ax.axvline(x=0.95, color="green", linestyle="--", label="Target (95%)")
        ax.legend()
        plt.tight_layout()

        if output:
            plt.savefig(output, dpi=150)
            print(f"Saved to {output}")
        else:
            plt.show()


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/guardian_lineage.json"
    viz = GuardianVisualizer(lineage_path=path)
    viz.plot_fitness_trend("data/fitness_trend.png")
    viz.plot_specialization_heatmap("data/specialization_heatmap.png")
    viz.plot_detection_by_scenario("data/detection_by_scenario.png")
