import argparse
from pathlib import Path

from src.C1 import C1Config, run_c1_investigation
from src.C3.cases import CaseLoadError, list_case_ids, load_case


def run_one_case(case_id: str, config: C1Config) -> None:
    alert, log_paths = load_case(case_id)

    print("=" * 60)
    print("C1 CONVENTIONAL INVESTIGATION (deterministic, Zeek-only)")
    print("=" * 60)
    print(f"Case: {case_id}")
    print()

    trace = run_c1_investigation(
        alert=alert,
        log_paths=log_paths,
        config=config,
        case_id=case_id,
    )

    output_dir = Path("logs/c1")
    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / f"{case_id}_trace.json"
    trace.save(trace_path)

    print(f"Queries executed:   {trace.queries_executed}")
    print(f"Branches triggered: {trace.branches_triggered}")
    print(f"Rules fired:        {trace.rules_fired}")
    print(f"Trace saved to:     {trace_path}")

    print()
    print("-" * 60)
    print("FINAL REPORT")
    print("-" * 60)
    for key, value in trace.final_report.items():
        print(f"\n{key}:")
        print(value)


def main():
    parser = argparse.ArgumentParser(
        description="Run the C1 (conventional, deterministic Zeek-only) "
        "baseline investigation for one or more scenario cases."
    )
    parser.add_argument(
        "case_id",
        nargs="?",
        default=None,
        help="Case to run, e.g. D1-C1. Omit with --all to run every case "
        "in scenarios/cases/.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every case found in scenarios/cases/, in order.",
    )
    args = parser.parse_args()

    if not args.case_id and not args.all:
        parser.error("pass a case_id (e.g. D1-C1) or --all")

    config = C1Config()
    case_ids = list_case_ids() if args.all else [args.case_id]

    for case_id in case_ids:
        try:
            run_one_case(case_id, config)
        except CaseLoadError as exc:
            print(f"Skipping {case_id}: {exc}")
        print()


if __name__ == "__main__":
    main()
