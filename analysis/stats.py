import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats as sps
from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests

DATA_DIR = Path(__file__).resolve().parent / "data"
SCORES_PATH = DATA_DIR / "scores.csv"
RESULTS_PATH = DATA_DIR / "stats_results.json"

PAIRS = [("C1", "C2"), ("C2", "C3"), ("C3", "C4"), ("C1", "C4")]
CONDITIONS = ["C1", "C2", "C3", "C4"]

CONTINUOUS_METRICS = [
    "duration_seconds",
    "clarity_mean",
    "grounding_precision",
    "attack_step_recall",
    "hallucination_rate",
]
BINARY_METRICS = [
    "non_completion",
]

ALPHA = 0.05
MIN_N_FRIEDMAN = 5   # below this, a repeated-measures omnibus test isn't meaningful
MIN_N_PAIRWISE = 5


def load_wide(metric: str) -> pd.DataFrame:
    """
    Pivot scores.csv to case_id x condition for one metric, coercing to
    numeric. Rows with any missing value are NOT dropped here -- callers
    decide per-test which subset of cases to use (Friedman needs all 4
    conditions present; a pairwise test only needs the 2 it's comparing).
    """
    df = pd.read_csv(SCORES_PATH)
    df[metric] = pd.to_numeric(df[metric], errors="coerce")
    wide = df.pivot(index="case_id", columns="condition", values=metric)
    return wide.reindex(columns=CONDITIONS)


def kendalls_w(chi2: float, n: int, k: int) -> float:
    """Effect size for the Friedman test. n = subjects, k = conditions."""
    if n == 0 or k <= 1:
        return float("nan")
    return chi2 / (n * (k - 1))


def rank_biserial_from_wilcoxon(x: np.ndarray, y: np.ndarray) -> float:
    """
    Matched-pairs rank-biserial correlation: (sum of positive-difference
    ranks - sum of negative-difference ranks) / total rank sum.
    Computed directly from the signed ranks rather than back-derived from
    the Wilcoxon W statistic (scipy uses a min-of-the-two convention that's
    a pain to unwind), so this is self-contained and always right regardless
    of ties/zeros handling.
    """
    diff = x - y
    diff = diff[diff != 0]
    if len(diff) == 0:
        return float("nan")
    ranks = sps.rankdata(np.abs(diff))
    pos = ranks[diff > 0].sum()
    neg = ranks[diff < 0].sum()
    total = pos + neg
    if total == 0:
        return float("nan")
    return (pos - neg) / total


def run_friedman(metric: str) -> dict:
    wide = load_wide(metric)
    complete = wide.dropna(axis=0, how="any")
    n = len(complete)

    result = {"metric": metric, "n_complete_cases": n}

    if n < MIN_N_FRIEDMAN:
        result["status"] = (
            f"skipped: only {n} cases have {metric} recorded for all 4 "
            f"conditions (need >= {MIN_N_FRIEDMAN}). Fill in more of "
            f"scores.csv and re-run."
        )
        return result

    stat, p = sps.friedmanchisquare(
        *(complete[c].values for c in CONDITIONS)
    )
    w = kendalls_w(stat, n, len(CONDITIONS))

    result.update(
        status="ok",
        chi2=float(stat),
        df=len(CONDITIONS) - 1,
        p_value=float(p),
        significant=bool(p < ALPHA),
        kendalls_w=float(w),
    )
    return result


def run_wilcoxon_pairs(metric: str) -> list[dict]:
    wide = load_wide(metric)
    raw_results = []

    for a, b in PAIRS:
        pair_df = wide[[a, b]].dropna(axis=0, how="any")
        n = len(pair_df)
        entry = {"metric": metric, "pair": f"{a} vs {b}", "n_complete_pairs": n}

        if n < MIN_N_PAIRWISE:
            entry["status"] = (
                f"skipped: only {n} cases have {metric} for both {a} and "
                f"{b} (need >= {MIN_N_PAIRWISE})."
            )
            raw_results.append(entry)
            continue

        x, y = pair_df[a].values, pair_df[b].values
        if np.all(x == y):
            entry["status"] = "skipped: all paired differences are zero"
            raw_results.append(entry)
            continue

        stat, p = sps.wilcoxon(x, y, zero_method="wilcox", correction=False, method="auto")
        r = rank_biserial_from_wilcoxon(x, y)

        entry.update(
            status="ok",
            statistic=float(stat),
            p_value_raw=float(p),
            rank_biserial_r=float(r),
            median_diff=float(np.median(x - y)),
        )
        raw_results.append(entry)

    # Holm-Sidak across the pairs that actually ran, for this metric
    testable = [e for e in raw_results if e["status"] == "ok"]
    if testable:
        pvals = [e["p_value_raw"] for e in testable]
        reject, p_adj, _, _ = multipletests(pvals, alpha=ALPHA, method="holm-sidak")
        for e, p_corrected, sig in zip(testable, p_adj, reject):
            e["p_value_holm_sidak"] = float(p_corrected)
            e["significant"] = bool(sig)

    return raw_results


def run_mcnemar_pairs(metric: str) -> list[dict]:
    wide = load_wide(metric)
    raw_results = []

    for a, b in PAIRS:
        pair_df = wide[[a, b]].dropna(axis=0, how="any")
        n = len(pair_df)
        entry = {"metric": metric, "pair": f"{a} vs {b}", "n_complete_pairs": n}

        if n < MIN_N_PAIRWISE:
            entry["status"] = (
                f"skipped: only {n} cases have {metric} for both {a} and "
                f"{b} (need >= {MIN_N_PAIRWISE})."
            )
            raw_results.append(entry)
            continue

        x = pair_df[a].astype(int).values
        y = pair_df[b].astype(int).values

        # 2x2 contingency table of discordant/concordant pairs
        both_1 = int(np.sum((x == 1) & (y == 1)))
        a_only = int(np.sum((x == 1) & (y == 0)))   # b in McNemar notation
        b_only = int(np.sum((x == 0) & (y == 1)))   # c in McNemar notation
        both_0 = int(np.sum((x == 0) & (y == 0)))
        table = [[both_1, a_only], [b_only, both_0]]

        discordant = a_only + b_only
        if discordant == 0:
            entry["status"] = "skipped: no discordant pairs (identical outcomes on both conditions)"
            raw_results.append(entry)
            continue

        # exact binomial version, appropriate for small N
        res = mcnemar(table, exact=True)
        cohens_g = abs(a_only - b_only) / discordant

        entry.update(
            status="ok",
            contingency_table={"both_1": both_1, f"{a}_only": a_only, f"{b}_only": b_only, "both_0": both_0},
            statistic=float(res.statistic),
            p_value_raw=float(res.pvalue),
            cohens_g=float(cohens_g),
        )
        raw_results.append(entry)

    testable = [e for e in raw_results if e["status"] == "ok"]
    if testable:
        pvals = [e["p_value_raw"] for e in testable]
        reject, p_adj, _, _ = multipletests(pvals, alpha=ALPHA, method="holm-sidak")
        for e, p_corrected, sig in zip(testable, p_adj, reject):
            e["p_value_holm_sidak"] = float(p_corrected)
            e["significant"] = bool(sig)

    return raw_results


def main():
    if not SCORES_PATH.exists():
        raise SystemExit(f"{SCORES_PATH} not found -- run analysis/ingest.py first.")

    results = {"continuous": {}, "binary": {}}

    print("=" * 70)
    print("CONTINUOUS METRICS: Friedman omnibus -> Wilcoxon pairwise (Holm-Sidak)")
    print("=" * 70)
    for metric in CONTINUOUS_METRICS:
        friedman_result = run_friedman(metric)
        print(f"\n[{metric}] Friedman: {friedman_result.get('status', friedman_result)}")
        if friedman_result.get("status") == "ok":
            print(
                f"  chi2={friedman_result['chi2']:.3f}, df={friedman_result['df']}, "
                f"p={friedman_result['p_value']:.4f}, Kendall's W={friedman_result['kendalls_w']:.3f}, "
                f"significant={friedman_result['significant']}"
            )

        pairwise = None
        if friedman_result.get("significant"):
            pairwise = run_wilcoxon_pairs(metric)
            for e in pairwise:
                if e["status"] == "ok":
                    print(
                        f"    {e['pair']}: n={e['n_complete_pairs']}, "
                        f"p_raw={e['p_value_raw']:.4f}, p_holm_sidak={e['p_value_holm_sidak']:.4f}, "
                        f"r={e['rank_biserial_r']:.3f}, significant={e['significant']}"
                    )
                else:
                    print(f"    {e['pair']}: {e['status']}")
        elif friedman_result.get("status") == "ok":
            print("  (Friedman not significant -- pairwise tests not run, per the design's decision rule)")

        results["continuous"][metric] = {"friedman": friedman_result, "pairwise": pairwise}

    print("\n" + "=" * 70)
    print("BINARY METRICS: pairwise McNemar's exact test (Holm-Sidak)")
    print("=" * 70)
    for metric in BINARY_METRICS:
        pairwise = run_mcnemar_pairs(metric)
        print(f"\n[{metric}]")
        for e in pairwise:
            if e["status"] == "ok":
                print(
                    f"    {e['pair']}: n={e['n_complete_pairs']}, table={e['contingency_table']}, "
                    f"p_raw={e['p_value_raw']:.4f}, p_holm_sidak={e['p_value_holm_sidak']:.4f}, "
                    f"Cohen's g={e['cohens_g']:.3f}, significant={e['significant']}"
                )
            else:
                print(f"    {e['pair']}: {e['status']}")
        results["binary"][metric] = {"pairwise": pairwise}

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()