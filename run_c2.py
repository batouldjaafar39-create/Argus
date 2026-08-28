import argparse
from pathlib import Path

from src.C2 import C2Config, run_c2_investigation
from src.C3.cases import CaseLoadError, list_case_ids, load_case


def run_one_case(case_id: str, config: C2Config) -> None:
    # load_case also resolves log_paths, but C2 has no Zeek access by
    # design -- we deliberately discard them here. Loading through the
    # same case loader (rather than reading the alert JSON directly)
    # keeps the "no CAPTURE_TIMESTAMP placeholder left unfilled" check
    # applied uniformly across C2/C3/Argus.
    alert, _log_paths = load_case(case_id)

    print("=" * 60)
    print("C2 BASELINE INVESTIGATION (LLM-only, no Zeek)")
    print("=" * 60)
    print(f"Model: {config.model_hf_repo}")
    print(f"Case:  {case_id}")
    print()

    print("Starting investigation...")
    print("This may take a minute because llama-cli is running locally.")
    print()

    trace = run_c2_investigation(
        alert=alert,
        config=config,
        case_id=case_id,
    )

    output_dir = Path("logs/c2")
    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / f"{case_id}_trace.json"
    trace.save(trace_path)

    print()
    print("=" * 60)
    print("C2 INVESTIGATION COMPLETE")
    print("=" * 60)
    print(f"Case:                  {trace.case_id}")
    print(f"Duration:              {trace.duration_seconds:.2f} seconds")
    print(f"Correction rounds:     {trace.correction_round_count}")
    print(f"JSON retries:          {trace.json_retry_count}")
    print(f"Termination:           {trace.terminated_reason}")
    print(f"Trace saved to:        {trace_path}")

    print()
    print("-" * 60)
    print("FINAL REPORT")
    print("-" * 60)

    if trace.final_report is None:
        print("No final report was produced.")
    else:
        for key, value in trace.final_report.items():
            print(f"\n{key}:")
            print(value)


def main():
    parser = argparse.ArgumentParser(
        description="Run the C2 (LLM-only, no Zeek) baseline investigation "
        "for one or more scenario cases."
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

    config = C2Config()
    case_ids = list_case_ids() if args.all else [args.case_id]

    for case_id in case_ids:
        try:
            run_one_case(case_id, config)
        except CaseLoadError as exc:
            print(f"Skipping {case_id}: {exc}")
        print()


if __name__ == "__main__":
    main()
