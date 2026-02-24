"""Load Guardian Gym encrypted databases, compute stats, and generate reports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


class GuardianAnalyzer:
    """Analyze Guardian Dojo training results from the encrypted SQLite database.

    Note: The Swift side stores records as AES-256-GCM encrypted blobs.
    For analysis, export records to JSON first using the CLI:
        guardian-dojo stats --db-path data/guardian_dojo.db
    Or use the JSON lineage file directly.
    """

    def __init__(self, lineage_path: str = "data/guardian_lineage.json"):
        self.lineage_path = Path(lineage_path)
        self._lineage: dict | None = None

    def load_lineage(self) -> dict:
        """Load the guardian lineage JSON file."""
        if self._lineage is None:
            with open(self.lineage_path) as f:
                self._lineage = json.load(f)
        return self._lineage

    def generation_stats(self) -> pd.DataFrame:
        """Compute per-generation statistics from lineage data."""
        lineage = self.load_lineage()
        generations = lineage.get("generations", [])
        if not generations:
            return pd.DataFrame()

        rows = []
        for gen in generations:
            rows.append(
                {
                    "generation": gen["generation"],
                    "population_size": gen["populationSize"],
                    "best_fitness": gen["bestFitness"],
                    "avg_fitness": gen["avgFitness"],
                    "best_detection_rate": gen["bestDetectionRate"],
                    "best_fpr": gen["bestFalsePositiveRate"],
                    "distinct_specializations": gen["distinctSpecializations"],
                }
            )
        return pd.DataFrame(rows)

    def prompt_stats(self) -> pd.DataFrame:
        """Compute per-prompt statistics from lineage data."""
        lineage = self.load_lineage()
        prompts = lineage.get("prompts", [])
        if not prompts:
            return pd.DataFrame()

        rows = []
        for p in prompts:
            rows.append(
                {
                    "id": p["id"]["hash"],
                    "generation": p["generation"],
                    "specialization": p["specialization"],
                    "fitness": p["fitness"],
                    "detection_rate": p["detectionRate"],
                    "fpr": p["falsePositiveRate"],
                    "prompt_length": len(p["promptText"]),
                    "has_parent": p.get("parentId") is not None,
                    "mutation": p.get("mutationDescription", "seed"),
                }
            )
        return pd.DataFrame(rows)

    def specialization_breakdown(self) -> pd.DataFrame:
        """Count prompts by specialization across all generations."""
        df = self.prompt_stats()
        if df.empty:
            return df
        return (
            df.groupby(["generation", "specialization"])
            .size()
            .reset_index(name="count")
            .pivot(index="generation", columns="specialization", values="count")
            .fillna(0)
            .astype(int)
        )

    def fitness_trend(self) -> pd.DataFrame:
        """Extract best and average fitness per generation."""
        df = self.generation_stats()
        if df.empty:
            return df
        return df[["generation", "best_fitness", "avg_fitness", "best_detection_rate", "best_fpr"]]

    def report(self) -> str:
        """Generate a text summary report."""
        gen_df = self.generation_stats()
        if gen_df.empty:
            return "No generation data found."

        lines = ["=== Guardian Gym Analysis Report ===", ""]

        lines.append(f"Total generations: {len(gen_df)}")
        lines.append(f"Best fitness achieved: {gen_df['best_fitness'].max():.3f}")
        lines.append(f"Best detection rate: {gen_df['best_detection_rate'].max():.1%}")
        lines.append(f"Lowest FPR: {gen_df['best_fpr'].min():.1%}")
        lines.append("")

        # Fitness progression
        if len(gen_df) >= 2:
            first = gen_df.iloc[0]
            last = gen_df.iloc[-1]
            lines.append("Fitness progression:")
            lines.append(f"  Gen 0:  best={first['best_fitness']:.3f}  avg={first['avg_fitness']:.3f}")
            lines.append(f"  Gen {int(last['generation'])}:  best={last['best_fitness']:.3f}  avg={last['avg_fitness']:.3f}")
            improvement = last["best_fitness"] - first["best_fitness"]
            lines.append(f"  Improvement: {improvement:+.3f}")

        # Specialization diversity
        prompt_df = self.prompt_stats()
        if not prompt_df.empty:
            lines.append("")
            lines.append("Specialization distribution (latest generation):")
            latest_gen = prompt_df["generation"].max()
            latest = prompt_df[prompt_df["generation"] == latest_gen]
            for spec, count in latest["specialization"].value_counts().items():
                lines.append(f"  {spec}: {count}")

        return "\n".join(lines)


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/guardian_lineage.json"
    analyzer = GuardianAnalyzer(lineage_path=path)
    print(analyzer.report())
