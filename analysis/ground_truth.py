import json
import re
from pathlib import Path

import openpyxl

REPO_ROOT = Path(__file__).resolve().parent.parent
XLSX_PATH = REPO_ROOT / "emulation-plans" / "apt29.xlsx"
DATA_DIR = Path(__file__).resolve().parent / "data"
GT_MD_DIR = Path(__file__).resolve().parent / "ground_truth"

ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# case_id -> (day sheet, case name, (start_major, start_minor), (end_major, end_minor), declared step count)
# Declared step count is the number of UNIQUE step labels in range (rows sharing
# a step label, e.g. two "2.A" rows for entering/exiting a shell, count once).
CASE_RANGES = {
    "D1-C1": ("day1", "Initial Access & Rapid Collection",        (1, "A"),  (2, "B"),  4),
    "D1-C2": ("day1", "Toolkit Deployment & UAC Bypass",          (3, "A"),  (4, "C"),  6),
    "D1-C3": ("day1", "Persistence & Credential Theft",           (5, "A"),  (6, "C"),  5),
    "D1-C4": ("day1", "Lateral Movement to NASHUA",                (7, "A"),  (8, "C"),  5),
    "D1-C5": ("day1", "Secondary Host Collection (NASHUA)",        (9, "A"),  (9, "C"),  3),
    "D1-C6": ("day1", "Reboot Persistence Trigger",                (10, "A"), (10, "B"), 2),
    "D2-C1": ("day2", "Spearphishing & Local Enumeration",         (11, "A"), (13, "D"), 8),
    "D2-C2": ("day2", "Privilege Escalation & Mimikatz",           (14, "A"), (15, "A"), 3),
    "D2-C3": ("day2", "Domain Lateral Movement & DC Compromise",   (16, "A"), (16, "D"), 4),
    "D2-C4": ("day2", "OneDrive Cloud Exfiltration",               (17, "A"), (18, "A"), 4),
    "D2-C5": ("day2", "Golden Ticket & Anti-Forensics",            (19, "A"), (20, "B"), 5),
}


def parse_step_id(raw) -> tuple[int, str] | None:
    """'1.A' -> (1, 'A'). Returns None for setup rows (Step == 0) or blanks."""
    if raw is None:
        return None
    s = str(raw).strip()
    if s in ("", "0", "Step"):
        return None
    m = re.match(r"^(\d+)\.([A-Za-z]+)$", s)
    if not m:
        return None
    return int(m.group(1)), m.group(2).upper()


def load_sheet_rows(ws) -> list[dict]:
    rows = []
    for row in ws.iter_rows(min_row=2, values_only=True):  # skip header
        stage, technique, step_raw, description, hands_on, user, source, target = row
        step_id = parse_step_id(step_raw)
        if step_id is None:
            continue  # setup / infrastructure row, not an attack step
        rows.append({
            "step_id": f"{step_id[0]}.{step_id[1]}",
            "step_key": step_id,
            "stage": stage,
            "technique": technique,
            "description": (description or "").strip(),
            "source": source,
            "target": target,
            "attack_technique_ids": sorted(set(ATTACK_ID_RE.findall(description or ""))),
        })
    return rows


def scope_case(all_rows: list[dict], start: tuple, end: tuple) -> list[dict]:
    return [r for r in all_rows if start <= r["step_key"] <= end]


def build_markdown(case_id: str, meta: dict, steps: list[dict]) -> str:
    lines = [
        f"# {case_id}: {meta['case_name']}",
        "",
        f"**Step range:** {meta['step_range']}  ",
        f"**Ground-truth step count:** {meta['step_count']}  ",
        f"**ATT&CK techniques involved:** {', '.join(meta['attack_technique_ids']) or '(none tagged)'}",
        "",
        "---",
        "",
    ]
    seen_step_ids = set()
    for s in steps:
        marker = ""
        if s["step_id"] in seen_step_ids:
            marker = " *(continuation of the same step)*"
        seen_step_ids.add(s["step_id"])

        lines.append(f"## Step {s['step_id']}{marker} -- {s['stage']}")
        if s["technique"]:
            lines.append(f"*Technique(s): {s['technique']}*")
        if s["attack_technique_ids"]:
            lines.append(f"**ATT&CK:** {', '.join(s['attack_technique_ids'])}")
        lines.append(f"**{s['source']} -> {s['target']}**")
        lines.append("")
        lines.append(s["description"])
        lines.append("")
    return "\n".join(lines)


def main():
    if not XLSX_PATH.exists():
        raise SystemExit(
            f"{XLSX_PATH} not found.\n"
            f"Place apt29.xlsx at emulation-plans/apt29.xlsx (matching the path "
            f"your Research Design doc references in Section 7.10.3), then re-run."
        )

    wb = openpyxl.load_workbook(XLSX_PATH, data_only=True)
    sheet_rows = {"day1": load_sheet_rows(wb["day1"]), "day2": load_sheet_rows(wb["day2"])}

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    GT_MD_DIR.mkdir(parents=True, exist_ok=True)

    output = {}
    print(f"{'case_id':<8} {'declared':>8} {'extracted':>10}  status")
    print("-" * 45)

    for case_id, (day, case_name, start, end, declared_count) in CASE_RANGES.items():
        steps = scope_case(sheet_rows[day], start, end)
        unique_step_ids = {s["step_id"] for s in steps}
        extracted_count = len(unique_step_ids)

        all_attack_ids = sorted({tid for s in steps for tid in s["attack_technique_ids"]})

        status = "OK" if extracted_count == declared_count else "MISMATCH -- check step_range / xlsx"
        print(f"{case_id:<8} {declared_count:>8} {extracted_count:>10}  {status}")

        meta = {
            "day": day,
            "case_name": case_name,
            "step_range": f"{start[0]}.{start[1]} - {end[0]}.{end[1]}",
            "step_count": extracted_count,
            "declared_step_count": declared_count,
            "attack_technique_ids": all_attack_ids,
        }
        output[case_id] = {**meta, "steps": steps}

        md = build_markdown(case_id, meta, steps)
        (GT_MD_DIR / f"{case_id}.md").write_text(md)

    out_path = DATA_DIR / "case_ground_truth.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote {out_path}")
    print(f"Wrote {len(CASE_RANGES)} readable case files to {GT_MD_DIR}/")


if __name__ == "__main__":
    main()