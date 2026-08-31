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

CONDITIONS = ["C1", "C2", "C3", "Argus"]

# All planned paired comparisons.
PAIRS = [
    ("C1", "C2"),
    ("C1", "C3"),
    ("C1", "Argus"),
    ("C2", "C3"),
    ("C2", "Argus"),
    ("C3", "Argus"),
]

# Primary outcomes from the research design.
PRIMARY_METRICS = [
    "duration_seconds",
    "clarity_mean",
    "grounding_precision"
]

# Supporting correctness / credibility measures.
SECONDARY_METRICS = [
    "attack_step_recall",
    "hallucination_rate",
]

# Binary completion outcome.
BINARY_METRICS = [
    "non_completion",
]

ALPHA = 0.05


# ---------------------------------------------------------------------
# DATA LOADING
# ---------------------------------------------------------------------

def load_scores() -> pd.DataFrame:
    """Load and validate the paired evaluation table."""

    if not SCORES_PATH.exists():
        raise SystemExit(
            f"{SCORES_PATH} not found -- run analysis/ingest.py first."
        )

    df = pd.read_csv(SCORES_PATH)

    required = {"case_id", "condition"}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"scores.csv is missing required columns: {sorted(missing)}"
        )

    # The experimental design requires one observation per
    # case × condition.
    duplicated = df.duplicated(
        subset=["case_id", "condition"],
        keep=False,
    )

    if duplicated.any():
        duplicates = df.loc[
            duplicated,
            ["case_id", "condition"],
        ].sort_values(["case_id", "condition"])

        raise ValueError(
            "Duplicate case/condition observations found:\n"
            f"{duplicates.to_string(index=False)}"
        )

    return df


def load_wide(metric: str) -> pd.DataFrame:
    """
    Convert scores.csv into:

        rows    = investigation cases
        columns = C1, C2, C3, Argus

    Missing values remain missing so each statistical test can use
    the appropriate paired subset.
    """

    df = load_scores()

    if metric not in df.columns:
        raise ValueError(
            f"Metric '{metric}' is not present in scores.csv."
        )

    df = df.copy()
    df[metric] = pd.to_numeric(df[metric], errors="coerce")

    wide = df.pivot(
        index="case_id",
        columns="condition",
        values=metric,
    )

    return wide.reindex(columns=CONDITIONS)


# ---------------------------------------------------------------------
# DESCRIPTIVE STATISTICS
# ---------------------------------------------------------------------

def descriptive_stats(wide: pd.DataFrame) -> dict:
    """Return median, IQR, mean and available n for every condition."""

    result = {}

    for condition in CONDITIONS:
        values = pd.to_numeric(
            wide[condition],
            errors="coerce",
        ).dropna()

        if len(values) == 0:
            result[condition] = {
                "n": 0,
                "median": None,
                "iqr": None,
                "mean": None,
            }
            continue

        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)

        result[condition] = {
            "n": int(len(values)),
            "median": float(values.median()),
            "iqr": float(q3 - q1),
            "mean": float(values.mean()),
        }

    return result


# ---------------------------------------------------------------------
# EFFECT SIZES
# ---------------------------------------------------------------------

def kendalls_w(chi2: float, n: int, k: int) -> float:
    """
    Kendall's W for the Friedman test.

    W = chi-square / [n(k - 1)]
    """

    if n <= 0 or k <= 1:
        return float("nan")

    return float(chi2 / (n * (k - 1)))


def rank_biserial_from_wilcoxon(
    x: np.ndarray,
    y: np.ndarray,
) -> float:
    """
    Matched-pairs rank-biserial correlation.

    Positive values mean x tends to be larger than y.
    Negative values mean x tends to be smaller than y.
    """

    diff = np.asarray(x, dtype=float) - np.asarray(y, dtype=float)

    # Wilcoxon ignores zero differences.
    diff = diff[diff != 0]

    if len(diff) == 0:
        return float("nan")

    ranks = sps.rankdata(np.abs(diff))

    positive = ranks[diff > 0].sum()
    negative = ranks[diff < 0].sum()

    total = positive + negative

    if total == 0:
        return float("nan")

    return float((positive - negative) / total)


# ---------------------------------------------------------------------
# FRIEDMAN OMNIBUS TEST
# ---------------------------------------------------------------------

def run_friedman(metric: str) -> dict:
    """
    Friedman test across C1, C2, C3 and Argus.

    Only cases with observations for all four conditions are included.
    """

    wide = load_wide(metric)

    complete = wide.dropna(
        subset=CONDITIONS,
        how="any",
    )

    n = len(complete)
    k = len(CONDITIONS)

    result = {
        "metric": metric,
        "test": "Friedman",
        "n_complete_cases": int(n),
        "conditions": CONDITIONS,
        "descriptive": descriptive_stats(wide),
    }

    if n < 2:
        result["status"] = "skipped: insufficient complete paired cases"
        return result

    statistic, p_value = sps.friedmanchisquare(
        *(complete[c].to_numpy() for c in CONDITIONS)
    )

    w = kendalls_w(
        float(statistic),
        n,
        k,
    )

    result.update(
        {
            "status": "ok",
            "chi2": float(statistic),
            "df": k - 1,
            "p_value": float(p_value),
            "significant": bool(p_value < ALPHA),
            "kendalls_w": w,
            "decision_rule": (
                "Pairwise Wilcoxon tests are performed only when "
                "the Friedman omnibus test is significant."
            ),
        }
    )

    return result


# ---------------------------------------------------------------------
# WILCOXON POST-HOC TESTS
# ---------------------------------------------------------------------

def run_wilcoxon_pairs(metric: str) -> list[dict]:
    """
    Paired Wilcoxon signed-rank tests for all planned condition pairs.

    Multiplicity is controlled across the six pairwise comparisons
    using Holm's method.
    """

    wide = load_wide(metric)
    results = []

    for a, b in PAIRS:

        pair_df = wide[[a, b]].dropna(
            subset=[a, b],
            how="any",
        )

        n = len(pair_df)

        entry = {
            "metric": metric,
            "pair": f"{a} vs {b}",
            "n_complete_pairs": int(n),
            "test": "Wilcoxon signed-rank",
        }

        if n < 2:
            entry["status"] = (
                "skipped: insufficient paired observations"
            )
            results.append(entry)
            continue

        x = pair_df[a].to_numpy(dtype=float)
        y = pair_df[b].to_numpy(dtype=float)

        differences = x - y

        if np.all(differences == 0):
            entry["status"] = (
                "skipped: all paired differences are zero"
            )
            results.append(entry)
            continue

        statistic, p_value = sps.wilcoxon(
            x,
            y,
            zero_method="wilcox",
            correction=False,
            alternative="two-sided",
            method="auto",
        )

        effect = rank_biserial_from_wilcoxon(x, y)

        entry.update(
            {
                "status": "ok",
                "statistic": float(statistic),
                "p_value_raw": float(p_value),
                "rank_biserial_r": effect,
                "median_difference": float(
                    np.median(differences)
                ),
                "iqr_difference": float(
                    np.percentile(differences, 75)
                    - np.percentile(differences, 25)
                ),
            }
        )

        results.append(entry)

    # Holm correction across the six planned comparisons that
    # actually produced a test statistic.
    testable = [
        r for r in results
        if r["status"] == "ok"
    ]

    if testable:

        p_values = [
            r["p_value_raw"]
            for r in testable
        ]

        reject, adjusted, _, _ = multipletests(
            p_values,
            alpha=ALPHA,
            method="holm",
        )

        for entry, p_adj, sig in zip(
            testable,
            adjusted,
            reject,
        ):
            entry["p_value_holm"] = float(p_adj)
            entry["significant_after_holm"] = bool(sig)

    return results


# ---------------------------------------------------------------------
# COCHRAN'S Q TEST
# ---------------------------------------------------------------------

def run_cochran_q(metric: str) -> dict:
    """
    Cochran's Q test for a binary outcome measured on the same
    investigation cases under all four conditions.

    This is the binary analogue of the Friedman omnibus test.
    """

    wide = load_wide(metric)

    complete = wide.dropna(
        subset=CONDITIONS,
        how="any",
    )

    n = len(complete)

    result = {
        "metric": metric,
        "test": "Cochran's Q",
        "n_complete_cases": int(n),
        "conditions": CONDITIONS,
        "descriptive": {
            condition: (
                int(complete[condition].sum())
                if condition in complete
                else None
            )
            for condition in CONDITIONS
        },
    }

    if n < 2:
        result["status"] = (
            "skipped: insufficient complete paired cases"
        )
        return result

    data = complete[CONDITIONS].astype(int).to_numpy()

    # Cochran's Q calculation.
    #
    # N = number of subjects
    # k = number of treatments/conditions
    #
    # Q = (k(k-1) * [k*sum(C_j^2) - T^2])
    #     / [k*T - sum(R_i^2)]
    #
    # where:
    # C_j = column totals
    # R_i = row totals
    # T   = grand total
    k = data.shape[1]

    column_totals = data.sum(axis=0)
    row_totals = data.sum(axis=1)
    grand_total = data.sum()

    numerator = (
        k
        * (k - 1)
        * (
            k * np.sum(column_totals ** 2)
            - grand_total ** 2
        )
    )

    denominator = (
        k * grand_total
        - np.sum(row_totals ** 2)
    )

    if denominator == 0:
        result["status"] = (
            "skipped: Cochran's Q denominator is zero"
        )
        return result

    q = numerator / denominator

    p_value = sps.chi2.sf(
        q,
        df=k - 1,
    )

    result.update(
        {
            "status": "ok",
            "q_statistic": float(q),
            "df": k - 1,
            "p_value": float(p_value),
            "significant": bool(p_value < ALPHA),
            "decision_rule": (
                "Pairwise McNemar tests are performed only when "
                "the Cochran's Q omnibus test is significant."
            ),
        }
    )

    return result


# ---------------------------------------------------------------------
# MCNEMAR POST-HOC TESTS
# ---------------------------------------------------------------------

def run_mcnemar_pairs(metric: str) -> list[dict]:
    """
    Exact paired McNemar tests after a significant Cochran's Q test.

    Holm correction is applied across the six planned pairwise
    comparisons.
    """

    wide = load_wide(metric)
    results = []

    for a, b in PAIRS:

        pair_df = wide[[a, b]].dropna(
            subset=[a, b],
            how="any",
        )

        n = len(pair_df)

        entry = {
            "metric": metric,
            "pair": f"{a} vs {b}",
            "n_complete_pairs": int(n),
            "test": "McNemar exact",
        }

        if n < 2:
            entry["status"] = (
                "skipped: insufficient paired observations"
            )
            results.append(entry)
            continue

        x = pair_df[a].astype(int).to_numpy()
        y = pair_df[b].astype(int).to_numpy()

        both_1 = int(np.sum((x == 1) & (y == 1)))
        a_only = int(np.sum((x == 1) & (y == 0)))
        b_only = int(np.sum((x == 0) & (y == 1)))
        both_0 = int(np.sum((x == 0) & (y == 0)))

        discordant = a_only + b_only

        entry["contingency_table"] = {
            "both_1": both_1,
            f"{a}_only": a_only,
            f"{b}_only": b_only,
            "both_0": both_0,
        }

        if discordant == 0:
            entry["status"] = (
                "skipped: no discordant pairs"
            )
            results.append(entry)
            continue

        table = [
            [both_1, a_only],
            [b_only, both_0],
        ]

        test = mcnemar(
            table,
            exact=True,
        )

        # Directional paired difference:
        # positive means more non-completions under condition a.
        direction = (a_only - b_only)

        # Cohen's g for paired binary outcomes.
        cohens_g = abs(direction) / discordant

        entry.update(
            {
                "status": "ok",
                "statistic": float(test.statistic),
                "p_value_raw": float(test.pvalue),
                "cohens_g": float(cohens_g),
                "discordant_pairs": int(discordant),
                "direction_a_minus_b": int(direction),
            }
        )

        results.append(entry)

    testable = [
        r for r in results
        if r["status"] == "ok"
    ]

    if testable:

        p_values = [
            r["p_value_raw"]
            for r in testable
        ]

        reject, adjusted, _, _ = multipletests(
            p_values,
            alpha=ALPHA,
            method="holm",
        )

        for entry, p_adj, sig in zip(
            testable,
            adjusted,
            reject,
        ):
            entry["p_value_holm"] = float(p_adj)
            entry["significant_after_holm"] = bool(sig)

    return results


# ---------------------------------------------------------------------
# MAIN ANALYSIS
# ---------------------------------------------------------------------

def analyze_continuous_metric(
    metric: str,
    primary: bool,
) -> dict:

    friedman = run_friedman(metric)

    pairwise = None

    if friedman.get("status") == "ok":

        if friedman.get("significant"):
            pairwise = run_wilcoxon_pairs(metric)
        else:
            pairwise = {
                "status": (
                    "not_run: Friedman omnibus test was not significant"
                ),
                "comparisons": [],
            }

    return {
        "role": "primary" if primary else "secondary",
        "friedman": friedman,
        "pairwise": pairwise,
    }


def analyze_binary_metric(metric: str) -> dict:

    cochran = run_cochran_q(metric)

    pairwise = None

    if cochran.get("status") == "ok":

        if cochran.get("significant"):
            pairwise = run_mcnemar_pairs(metric)
        else:
            pairwise = {
                "status": (
                    "not_run: Cochran's Q omnibus test "
                    "was not significant"
                ),
                "comparisons": [],
            }

    return {
        "role": "secondary_binary",
        "cochran_q": cochran,
        "pairwise": pairwise,
    }


def main():

    print("=" * 78)
    print("PAIRED COMPARISON OF C1, C2, C3 AND ARGUS")
    print("11 paired investigation cases")
    print("=" * 78)

    results = {
        "design": {
            "n_cases_planned": 11,
            "conditions": CONDITIONS,
            "paired_design": True,
            "alpha": ALPHA,
            "primary_omnibus": "Friedman",
            "primary_posthoc": (
                "paired Wilcoxon signed-rank with Holm correction"
            ),
            "binary_omnibus": "Cochran's Q",
            "binary_posthoc": (
                "exact McNemar with Holm correction"
            ),
        },
        "primary": {},
        "secondary": {},
        "binary": {},
    }

    # ---------------------------------------------------------------
    # PRIMARY CONTINUOUS OUTCOMES
    # ---------------------------------------------------------------

    print("\n" + "=" * 78)
    print("PRIMARY OUTCOMES")
    print("=" * 78)

    for metric in PRIMARY_METRICS:

        print(f"\n[{metric}]")

        analysis = analyze_continuous_metric(
            metric,
            primary=True,
        )

        friedman = analysis["friedman"]

        print(
            f"  Friedman: {friedman.get('status')}"
        )

        if friedman.get("status") == "ok":

            print(
                f"  n={friedman['n_complete_cases']}, "
                f"chi2={friedman['chi2']:.3f}, "
                f"df={friedman['df']}, "
                f"p={friedman['p_value']:.4f}, "
                f"Kendall's W={friedman['kendalls_w']:.3f}"
            )

            if friedman["significant"]:

                print(
                    "  Friedman significant -> "
                    "running paired Wilcoxon tests."
                )

                for entry in analysis["pairwise"]:

                    if entry["status"] == "ok":

                        print(
                            f"    {entry['pair']}: "
                            f"n={entry['n_complete_pairs']}, "
                            f"p={entry['p_value_raw']:.4f}, "
                            f"Holm={entry['p_value_holm']:.4f}, "
                            f"r_rb={entry['rank_biserial_r']:.3f}"
                        )

                    else:
                        print(
                            f"    {entry['pair']}: "
                            f"{entry['status']}"
                        )

            else:

                print(
                    "  Friedman not significant -> "
                    "no pairwise tests."
                )

        results["primary"][metric] = analysis

    # ---------------------------------------------------------------
    # SECONDARY CONTINUOUS OUTCOMES
    # ---------------------------------------------------------------

    print("\n" + "=" * 78)
    print("SECONDARY CORRECTNESS / GROUNDING OUTCOMES")
    print("=" * 78)

    for metric in SECONDARY_METRICS:

        print(f"\n[{metric}]")

        analysis = analyze_continuous_metric(
            metric,
            primary=False,
        )

        friedman = analysis["friedman"]

        print(
            f"  Friedman: {friedman.get('status')}"
        )

        if friedman.get("status") == "ok":

            print(
                f"  n={friedman['n_complete_cases']}, "
                f"chi2={friedman['chi2']:.3f}, "
                f"df={friedman['df']}, "
                f"p={friedman['p_value']:.4f}, "
                f"Kendall's W={friedman['kendalls_w']:.3f}"
            )

            if friedman["significant"]:

                print(
                    "  Friedman significant -> "
                    "running paired Wilcoxon tests."
                )

                for entry in analysis["pairwise"]:

                    if entry["status"] == "ok":

                        print(
                            f"    {entry['pair']}: "
                            f"n={entry['n_complete_pairs']}, "
                            f"p={entry['p_value_raw']:.4f}, "
                            f"Holm={entry['p_value_holm']:.4f}, "
                            f"r_rb={entry['rank_biserial_r']:.3f}"
                        )

                    else:

                        print(
                            f"    {entry['pair']}: "
                            f"{entry['status']}"
                        )

            else:

                print(
                    "  Friedman not significant -> "
                    "no pairwise tests."
                )

        results["secondary"][metric] = analysis

    # ---------------------------------------------------------------
    # BINARY NON-COMPLETION
    # ---------------------------------------------------------------

    print("\n" + "=" * 78)
    print("NON-COMPLETION")
    print("=" * 78)

    for metric in BINARY_METRICS:

        print(f"\n[{metric}]")

        analysis = analyze_binary_metric(metric)

        cochran = analysis["cochran_q"]

        print(
            f"  Cochran's Q: "
            f"{cochran.get('status')}"
        )

        if cochran.get("status") == "ok":

            print(
                f"  n={cochran['n_complete_cases']}, "
                f"Q={cochran['q_statistic']:.3f}, "
                f"df={cochran['df']}, "
                f"p={cochran['p_value']:.4f}"
            )

            if cochran["significant"]:

                print(
                    "  Cochran's Q significant -> "
                    "running exact McNemar tests."
                )

                for entry in analysis["pairwise"]:

                    if entry["status"] == "ok":

                        print(
                            f"    {entry['pair']}: "
                            f"p={entry['p_value_raw']:.4f}, "
                            f"Holm={entry['p_value_holm']:.4f}, "
                            f"g={entry['cohens_g']:.3f}"
                        )

                    else:

                        print(
                            f"    {entry['pair']}: "
                            f"{entry['status']}"
                        )

            else:

                print(
                    "  Cochran's Q not significant -> "
                    "no pairwise McNemar tests."
                )

        results["binary"][metric] = analysis

    # ---------------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------------

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        RESULTS_PATH,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            results,
            f,
            indent=2,
            allow_nan=False,
        )

    print(
        f"\nWrote statistical results to: "
        f"{RESULTS_PATH}"
    )


if __name__ == "__main__":
    main()