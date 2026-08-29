import csv
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "logs"
CASES_DIR = REPO_ROOT / "scenarios" / "cases"
OUT_DIR = Path(__file__).resolve().parent / "data"

# logs/<folder> -> canonical condition label used in the CSV
CONDITION_FOLDERS = {
    "c1": "C1",
    "c2": "C2",
    "c3": "C3",
    "argus": "C4",
}

# a trace's own summary.condition field isn't always the canonical label
# (e.g. Argus traces self-report "Argus" instead of "C4") -- normalize it.
CONDITION_ALIASES = {
    "C1": "C1",
    "C2": "C2",
    "C3": "C3",
    "C4": "C4",
    "ARGUS": "C4",
}

SCORE_COLUMNS = [
    "case_id",
    "condition",
    "duration_seconds",
    "rater_id",
    "evidence_identification",     # clarity rubric dim 1, 1-5
    "reasoning_traceability",      # clarity rubric dim 2, 1-5
    "uncertainty_communication",   # clarity rubric dim 3, 1-5
    "overall_usefulness",          # clarity rubric dim 4, 1-5
    "clarity_mean",                # auto-computed from the 4 dims above
    "grounding_precision",         # credibility: supported / total claims
    "attack_step_recall",          # credibility: steps identified / total
    "hallucination_rate",          # credibility: hallucinated / total claims
    "non_completion",              # 1 if investigation hit the step/time limit unresolved, else 0
    "notes",
]


def expected_case_ids() -> list[str]:
    if not CASES_DIR.exists():
        raise SystemExit(f"scenarios/cases not found at {CASES_DIR}")
    return sorted(p.stem for p in CASES_DIR.glob("*.json"))


def load_traces() -> dict[tuple[str, str], dict]:
    """Returns {(case_id, condition): trace_dict} for every trace file found."""
    traces = {}
    for folder, condition in CONDITION_FOLDERS.items():
        folder_path = LOGS_DIR / folder
        if not folder_path.exists():
            continue
        for trace_file in sorted(folder_path.glob("*_trace.json")):
            with open(trace_file) as f:
                trace = json.load(f)
            summary = trace.get("summary", {})
            case_id = summary.get("case_id", trace_file.stem.replace("_trace", ""))
            raw_condition = str(summary.get("condition", condition)).upper()
            norm_condition = CONDITION_ALIASES.get(raw_condition, condition)
            traces[(case_id, norm_condition)] = trace
    return traces


def build_scores_rows(case_ids: list[str], traces: dict) -> list[dict]:
    rows = []
    for case_id in case_ids:
        for condition in ("C1", "C2", "C3", "C4"):
            trace = traces.get((case_id, condition))
            row = {col: "" for col in SCORE_COLUMNS}
            row["case_id"] = case_id
            row["condition"] = condition
            if trace is not None:
                row["duration_seconds"] = trace.get("summary", {}).get("duration_seconds", "")
            rows.append(row)
    return rows


def build_report_texts(traces: dict) -> dict:
    out: dict[str, dict] = {}
    for (case_id, condition), trace in traces.items():
        out.setdefault(case_id, {})[condition] = trace.get("final_report", {})
    return out


def print_coverage(case_ids: list[str], traces: dict) -> None:
    conditions = ("C1", "C2", "C3", "C4")
    have = sum(1 for c in case_ids for cond in conditions if (c, cond) in traces)
    total = len(case_ids) * len(conditions)
    print(f"\nCoverage: {have}/{total} trace files found ({total - have} runs still to do)\n")

    header = "case_id".ljust(14) + "".join(c.center(6) for c in conditions)
    print(header)
    for case_id in case_ids:
        row = case_id.ljust(14)
        for cond in conditions:
            row += ("  X   " if (case_id, cond) in traces else "  .   ")
        print(row)

    # flag any traces that don't correspond to an expected case_id at all
    stray = sorted({cid for (cid, _cond) in traces if cid not in case_ids})
    if stray:
        print(f"\nNote: {len(stray)} trace(s) found with case_id not in scenarios/cases "
              f"(likely ad-hoc test runs, e.g. {stray}) -- excluded from the grid above "
              f"but included in report_texts.json for reference.")


def main():
    case_ids = expected_case_ids()
    traces = load_traces()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    scores_path = OUT_DIR / "scores.csv"
    rows = build_scores_rows(case_ids, traces)
    with open(scores_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCORE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {scores_path} ({len(rows)} rows = {len(case_ids)} cases x 4 conditions)")

    report_texts_path = OUT_DIR / "report_texts.json"
    with open(report_texts_path, "w") as f:
        json.dump(build_report_texts(traces), f, indent=2)
    print(f"Wrote {report_texts_path}")

    print_coverage(case_ids, traces)


if __name__ == "__main__":
    main()