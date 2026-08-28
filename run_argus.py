import argparse
from pathlib import Path

from src.Argus import ArgusConfig, run_argus_investigation
from src.C3.cases import CaseLoadError, list_case_ids, load_case


def run_one_case(case_id: str, config: ArgusConfig) -> None:
    alert, log_paths = load_case(case_id)

    print("=" * 60)
    print("ARGUS INVESTIGATION")
    print("=" * 60)
    print(f"Model: {config.model_hf_repo}")
    print(f"Case:  {case_id}")
    print(f"Max planning rounds: {config.max_planning_rounds}")
    print(f"Max revisions:       {config.max_revisions}")
    print()

    print("Zeek logs:")
    for tool_name, path in log_paths.items():
        print(f"  {tool_name}: {path}")
    print()

    trace = run_argus_investigation(
        alert=alert,
        log_paths=log_paths,
        config=config,
        case_id=case_id,
    )

    output_dir = Path("logs/argus")
    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / f"{case_id}_trace.json"
    trace.save(trace_path)

    print("\n" + "=" * 60)
    print("ARGUS INVESTIGATION COMPLETE")
    print("=" * 60)
    print(f"Case:              {trace.case_id}")
    print(f"Duration:          {trace.duration_seconds:.2f} seconds")
    print(f"Planning rounds:   {trace.planning_round_count}")
    print(f"Zeek queries:      {trace.zeek_query_count}")
    print(f"Tools queried:     {trace.tools_queried}")
    print(f"Analyst revisions: {trace.revision_count}")
    print(f"JSON retries:      {trace.json_retry_count}")
    print(f"Tool failures:     {trace.tool_call_failure_count}")
    print(f"Termination:       {trace.terminated_reason}")
    print(f"Trace saved to:    {trace_path}")
    print("\nFINAL REPORT")
    print("-" * 60)
    for key, value in (trace.final_report or {}).items():
        print(f"\n{key}:\n{value}")


def main():
    parser = argparse.ArgumentParser(
        description="Run the Argus multi-agent (planner + analyst) investigation "
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

    config = ArgusConfig()
    case_ids = list_case_ids() if args.all else [args.case_id]

    for case_id in case_ids:
        try:
            run_one_case(case_id, config)
        except CaseLoadError as exc:
            print(f"Skipping {case_id}: {exc}")
        print()


if __name__ == "__main__":
    main()