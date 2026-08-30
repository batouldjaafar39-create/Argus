
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent / "data"
SCORES_PATH = DATA_DIR / "scores.csv"
FIG_DIR = Path(__file__).resolve().parent / "figures"

CONDITIONS = ["C1", "C2", "C3", "C4"]
CONDITION_LABELS = {
    "C1": "C1\n(Zeek rules)",
    "C2": "C2\n(LLM-only)",
    "C3": "C3\n(fixed pipeline)",
    "C4": "C4\n(Argus)",
}
CONDITION_COLORS = {"C1": "#6b7280", "C2": "#f59e0b", "C3": "#3b82f6", "C4": "#16a34a"}

MIN_N_FOR_PLOT = 3  # below this a box/strip plot is misleading -- skip and warn


def load_scores() -> pd.DataFrame:
    if not SCORES_PATH.exists():
        raise SystemExit(f"{SCORES_PATH} not found -- run analysis/ingest.py first.")
    df = pd.read_csv(SCORES_PATH)
    numeric_cols = [
        "duration_seconds", "clarity_mean", "grounding_precision",
        "attack_step_recall", "hallucination_rate", "non_completion",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def _style_axis(ax, title, ylabel):
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.set_ylabel(ylabel, fontsize=10)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.3)


def plot_metric_comparison(df: pd.DataFrame, metric: str, title: str, ylabel: str, filename: str, log_scale: bool = False):
    """Box plot + jittered individual case points, one box per condition."""
    fig, ax = plt.subplots(figsize=(6, 4.5))

    per_condition = []
    counts = {}
    for cond in CONDITIONS:
        vals = df.loc[df["condition"] == cond, metric].dropna().values
        per_condition.append(vals)
        counts[cond] = len(vals)

    if all(n < MIN_N_FOR_PLOT for n in counts.values()):
        print(f"  [{metric}] skipped: fewer than {MIN_N_FOR_PLOT} values in every condition ({counts})")
        plt.close(fig)
        return

    positions = range(1, len(CONDITIONS) + 1)
    bp = ax.boxplot(
        per_condition, positions=positions, widths=0.5, showfliers=False,
        patch_artist=True, medianprops=dict(color="black", linewidth=1.5),
    )
    for patch, cond in zip(bp["boxes"], CONDITIONS):
        patch.set_facecolor(CONDITION_COLORS[cond])
        patch.set_alpha(0.35)

    rng = np.random.default_rng(0)
    for pos, cond, vals in zip(positions, CONDITIONS, per_condition):
        if len(vals) == 0:
            continue
        jitter = rng.uniform(-0.12, 0.12, size=len(vals))
        ax.scatter(np.full(len(vals), pos) + jitter, vals, color=CONDITION_COLORS[cond],
                    edgecolor="white", linewidth=0.5, s=40, zorder=3)

    ax.set_xticks(list(positions))
    ax.set_xticklabels([f"{CONDITION_LABELS[c]}\n(n={counts[c]})" for c in CONDITIONS], fontsize=8)
    if log_scale:
        ax.set_yscale("log")
    _style_axis(ax, title, ylabel)

    fig.tight_layout()
    out_path = FIG_DIR / filename
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"  wrote {out_path} (n per condition: {counts})")


def plot_rq4_tradeoff(df: pd.DataFrame, filename: str = "rq4_tradeoff.png"):
    """
    RQ4: speed vs credibility vs clarity trade-off.
    x = mean investigation time (log scale, since C1 is near-instant and
        C4 is ~2 orders of magnitude slower), y = mean grounding precision,
        marker size = mean clarity. One point per condition (aggregated
        across available cases), not per case -- this is a summary figure.
    """
    agg = df.groupby("condition").agg(
        time=("duration_seconds", "mean"),
        credibility=("grounding_precision", "mean"),
        clarity=("clarity_mean", "mean"),
        n=("duration_seconds", "count"),
    )
    agg = agg.reindex(CONDITIONS)

    if agg["time"].isna().all() or agg["credibility"].isna().all():
        print(f"  [rq4_tradeoff] skipped: not enough data yet (need duration_seconds and "
              f"grounding_precision for at least one case per condition)")
        return

    fig, ax = plt.subplots(figsize=(6.5, 5))
    for cond in CONDITIONS:
        row = agg.loc[cond]
        if pd.isna(row["time"]) or pd.isna(row["credibility"]):
            continue
        clarity = row["clarity"] if not pd.isna(row["clarity"]) else 3.0  # neutral default if not yet rated
        size = 200 + (clarity - 1) * 150  # scale 1-5 clarity to a visible marker size range
        ax.scatter(row["time"], row["credibility"], s=size, color=CONDITION_COLORS[cond],
                    alpha=0.75, edgecolor="black", linewidth=1, zorder=3, label=cond)
        ax.annotate(f"{cond} (n={int(row['n'])})", (row["time"], row["credibility"]),
                    textcoords="offset points", xytext=(10, 10), fontsize=9, fontweight="bold")

    ax.set_xscale("log")
    ax.set_xlabel("Mean investigation time, seconds (log scale)", fontsize=10)
    ax.set_ylabel("Mean grounding precision", fontsize=10)
    ax.set_title("RQ4: speed vs. credibility trade-off\n(marker size = mean clarity)", fontsize=12, fontweight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(alpha=0.3)
    fig.tight_layout()

    out_path = FIG_DIR / filename
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"  wrote {out_path}")


def plot_grounding_vs_hallucination(df: pd.DataFrame, filename: str = "grounding_vs_hallucination.png"):
    """Per-case scatter: grounding precision vs hallucination rate, colored by condition."""
    plot_df = df.dropna(subset=["grounding_precision", "hallucination_rate"])
    if len(plot_df) < MIN_N_FOR_PLOT:
        print(f"  [grounding_vs_hallucination] skipped: only {len(plot_df)} cases have both metrics "
              f"(need >= {MIN_N_FOR_PLOT})")
        return

    fig, ax = plt.subplots(figsize=(6, 5))
    for cond in CONDITIONS:
        sub = plot_df[plot_df["condition"] == cond]
        if len(sub) == 0:
            continue
        ax.scatter(sub["grounding_precision"], sub["hallucination_rate"], color=CONDITION_COLORS[cond],
                    label=f"{cond} (n={len(sub)})", s=60, alpha=0.8, edgecolor="white", linewidth=0.5)

    ax.set_xlabel("Grounding precision (supported / total claims)", fontsize=10)
    ax.set_ylabel("Hallucination rate (hallucinated / total claims)", fontsize=10)
    ax.set_title("Grounding precision vs. hallucination rate, per case", fontsize=12, fontweight="bold")
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=8, frameon=False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(alpha=0.3)
    fig.tight_layout()

    out_path = FIG_DIR / filename
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"  wrote {out_path}")


def plot_non_completion_rate(df: pd.DataFrame, filename: str = "non_completion_rate.png"):
    """Bar chart: proportion of cases that hit the step/time limit unresolved, per condition."""
    rates, counts = {}, {}
    for cond in CONDITIONS:
        vals = df.loc[df["condition"] == cond, "non_completion"].dropna()
        counts[cond] = len(vals)
        rates[cond] = vals.mean() if len(vals) > 0 else np.nan

    if all(pd.isna(v) for v in rates.values()):
        print("  [non_completion_rate] skipped: no non_completion values recorded yet")
        return

    fig, ax = plt.subplots(figsize=(5.5, 4))
    bars = ax.bar(
        CONDITIONS, [rates[c] if not pd.isna(rates[c]) else 0 for c in CONDITIONS],
        color=[CONDITION_COLORS[c] for c in CONDITIONS], alpha=0.8, edgecolor="black", linewidth=0.5,
    )
    for bar, cond in zip(bars, CONDITIONS):
        label = f"n={counts[cond]}" if not pd.isna(rates[cond]) else "no data"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02, label,
                ha="center", fontsize=8)

    ax.set_xticks(range(len(CONDITIONS)))
    ax.set_xticklabels([CONDITION_LABELS[c] for c in CONDITIONS], fontsize=8)
    ax.set_ylim(0, 1.15)
    _style_axis(ax, "Non-completion rate by condition", "Proportion of cases hitting the limit unresolved")
    fig.tight_layout()

    out_path = FIG_DIR / filename
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"  wrote {out_path}")


def main():
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    df = load_scores()

    print("Per-metric comparisons:")
    plot_metric_comparison(df, "duration_seconds", "Investigation time by condition", "Seconds (log scale)",
                            "time_by_condition.png", log_scale=True)
    plot_metric_comparison(df, "clarity_mean", "Explanation clarity by condition", "Clarity score (1-5)",
                            "clarity_by_condition.png")
    plot_metric_comparison(df, "grounding_precision", "Grounding precision by condition", "Supported / total claims",
                            "grounding_precision_by_condition.png")
    plot_metric_comparison(df, "attack_step_recall", "Attack-step recall by condition", "Steps identified / total",
                            "attack_step_recall_by_condition.png")
    plot_metric_comparison(df, "hallucination_rate", "Hallucination rate by condition", "Hallucinated / total claims",
                            "hallucination_rate_by_condition.png")

    print("\nTrade-off and relationship figures:")
    plot_rq4_tradeoff(df)
    plot_grounding_vs_hallucination(df)
    plot_non_completion_rate(df)

    print(f"\nAll available figures written to {FIG_DIR}")


if __name__ == "__main__":
    main()