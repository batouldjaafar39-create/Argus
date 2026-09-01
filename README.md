# Argus — AI-Assisted SOC Investigation

Argus is an AI-assisted Security Operations Center (SOC) investigation prototype designed to support analysts across an end-to-end investigation workflow. Instead of using an LLM only for alert interpretation, Argus combines an LLM planner, structured evidence retrieval through Zeek, an evidence ledger, evidence-grounded report generation, deterministic verification, and analyst-oriented explanations.

The research evaluates whether structuring an LLM investigation workflow provides benefits beyond simply giving the model access to security telemetry. The central evaluation dimensions are **investigation time, evidential credibility, and explanation clarity**.

## Research question

The study asks how an AI-assisted SOC investigation system can support analysts while balancing:

- **Time** — how quickly an investigation reaches a final report.
- **Credibility** — whether conclusions are supported by available telemetry and ground truth.
- **Clarity** — whether an analyst can understand and evaluate the investigation result.

The research design formulates four questions covering investigation efficiency, evidence-grounded investigation, analyst understanding, and the trade-off among these dimensions.

## Experimental design

The experiment uses a paired comparison across the same **11 investigation cases** under four conditions:

| Condition | Description |
|---|---|
| **C1 — Conventional** | Deterministic investigation using predefined logic and Zeek evidence |
| **C2 — LLM-only** | Qwen3-4B investigates the alert without access to Zeek |
| **C3 — LLM + Zeek** | Qwen3-4B can dynamically request Zeek evidence |
| **Argus** | Qwen3-4B uses the structured Argus investigation workflow and Zeek |

The progression is therefore:

**Conventional → LLM-only → LLM + Zeek → Argus**

This isolates the contribution of LLM reasoning, external evidence access, and structured investigation.

## Dataset

The experiment uses the **OTRF APT29 Detection Hackathon dataset**, based on the APT29 adversary emulation used in the MITRE ATT&CK Evaluations. The evaluation covers telemetry from both Day 1 and Day 2 and divides the emulation into 11 modular investigation cases covering 49 telemetry-producing attack steps.

Ground truth is derived from the accompanying `emulation-plans/apt29.xlsx` emulation plan. Ground truth is not exposed to any investigation condition during execution.

## Investigation workflow

### C3 — LLM + Zeek

C3 follows an adaptive loop in which the model receives an alert, forms a hypothesis, requests Zeek evidence, interprets the returned data, and may request further evidence before producing a report.

### Argus

Argus adds explicit structure around that process:

```text
Initial alert
     ↓
Scope investigation
     ↓
Generate hypotheses
     ↓
Identify required evidence
     ↓
Retrieve evidence through Zeek
     ↓
Validate evidence
     ↓
Update hypotheses
     ↓
Generate final report
     ↓
Deterministic evidence verification
     ↓
Revision when verification fails
```

The implementation uses an **evidence ledger** so retrieved evidence receives stable IDs such as `E001`, `E002`, etc. Final reports are required to cite those IDs, and the verification stage checks whether factual claims are adequately grounded.

## Model and execution

The LLM-based conditions use:

- **Model:** Qwen3-4B-GGUF, `Q4_K_M`
- **Backend:** `llama-cli` / local llama.cpp-compatible execution
- **Temperature:** 0.0
- **Top-p:** 0.9
- **Top-k:** 40
- **Seed:** 42
- **Local environment:** 16 GB RAM for the experimental setup
- **Paid API:** not required

Argus additionally uses bounded planning rounds, tool-call limits, JSON retries, context management, and report revisions to make failures explicit and reproducible.

## Evaluation metrics

### Primary outcomes

**Investigation time** is measured as the elapsed time from the initial alert to the final report.

**Explanation clarity** is scored on four dimensions using a 1–5 rubric:

1. Evidence identification
2. Reasoning traceability
3. Uncertainty communication
4. Overall usefulness

**Grounding precision** is computed from claim-level labels, using the proportion of report claims that are supported by the available evidence and ground truth.

### Secondary outcomes

- **Attack-step recall:** correctly identified ground-truth attack steps divided by the attack steps in the case.
- **Hallucination rate:** hallucinated or incorrect claims divided by total claims.
- **Non-completion:** whether an investigation fails to produce a final report within the predefined limits.

## Results

Across the 11 paired cases, Argus produced the strongest overall **clarity** and **attack-step recall**, while its main cost was **higher investigation time**. Argus also substantially improved grounding relative to C3, although it did not significantly outperform C1 on grounding precision.

### Primary results

| Metric | C1 | C2 | C3 | Argus | Friedman |
|---|---:|---:|---:|---:|---|
| Median time (s) | 0.021 | 29.462 | 357.242 | 519.877 | χ²(3)=30.382, p<0.001 |
| Mean clarity | 2.68 | 1.80 | 2.55 | **3.57** | χ²(3)=28.038, p<0.001 |
| Mean grounding precision | **0.859** | 0.768 | 0.714 | 0.841 | χ²(3)=13.188, p=0.004 |

All 11 cases were complete for the three primary metrics.

### Secondary results

| Metric | C1 | C2 | C3 | Argus | Friedman |
|---|---:|---:|---:|---:|---|
| Mean attack-step recall | 0.059 | 0.000 | 0.038 | **0.677** | χ²(3)=28.731, p<0.001 |
| Mean hallucination rate | 0.064 | **0.000** | 0.077 | 0.045 | χ²(3)=3.625, p=0.305 |
| Non-completion | 0/11 | 0/11 | 0/11 | 0/11 |  |

### Key pairwise findings

After the Friedman omnibus test, paired Wilcoxon signed-rank tests were performed with **Holm correction** across the six planned comparisons.

- **C3 vs Argus — clarity:** Argus was significantly clearer (`p = 0.0059` after Holm correction, rank-biserial `r = -1.00`).
- **C3 vs Argus — grounding precision:** Argus was significantly better grounded (`p = 0.0234`, rank-biserial `r = -0.964`).
- **C3 vs Argus — attack-step recall:** Argus was substantially better (`p = 0.0059`, rank-biserial `r = -1.00`).
- **C3 vs Argus — time:** the difference was not statistically significant (`p = 0.2402`), although Argus had a higher median time (519.9 s vs 357.2 s).
- **C1 vs Argus — grounding precision:** the difference was not statistically significant (`p = 0.6406`).
- **C1 vs Argus — clarity:** Argus was significantly clearer (`p = 0.0059`).

The complete statistical output is stored in [`analysis/data/stats_results.json`](analysis/data/stats_results.json), and the case-level scoring table is in [`analysis/data/scores.csv`](analysis/data/scores.csv).

## Interpretation of the hypotheses

### H1 — Investigation efficiency

**Not supported.** Argus did not reduce runtime relative to the conventional deterministic baseline. It also did not show a statistically significant runtime difference from C3, the simpler tool-enabled LLM condition. The structured workflow therefore improved other investigation properties without demonstrating a time reduction.

### H2 — Evidence-grounded credibility

**Partially supported.** Argus significantly improved grounding precision compared with C3 and achieved a much higher attack-step recall. However, its grounding precision was not significantly different from C1, and the conventional baseline had the highest mean grounding precision. The strongest evidence for Argus is therefore its improvement over the unstructured LLM+Zeek baseline rather than universal superiority on every credibility measure.

### H3 — Analyst understanding

**Supported by the clarity evaluation.** Argus achieved the highest mean clarity score (3.57/5), significantly outperforming C3 (2.55/5). Its reports also scored strongly across evidence identification and reasoning traceability.

### H4 — Integrated trade-off

**Supported.** The results show a clear trade-off: Argus required more computation/time than C3 while producing substantially better attack-step recall and clearer reports, with grounding precision recovering from C3's lower level. This supports the central research proposition that SOC investigation quality cannot be reduced to a single metric.

## Repository structure

```text
argus-soc/
├── src/
│   ├── Argus/          # structured Argus workflow
│   ├── C1/             # deterministic baseline
│   ├── C2/             # LLM-only baseline
│   ├── C3/             # LLM + Zeek baseline
│   └── zeek/           # Zeek parsers, schemas and query interface
├── scenarios/cases/    # 11 investigation cases
├── data/               # Zeek telemetry
├── logs/               # investigation traces
├── analysis/
│   ├── data/           # scores and statistical outputs
│   ├── figures/        # generated figures
│   ├── ingest.py       # score/report ingestion
│   ├── ground_truth.py # ground-truth processing
│   └── stats.py        # statistical analysis
├── run_c1.py
├── run_c2.py
├── run_c3.py
├── run_argus.py
└── test_*.py
```

## Reproducibility

The experiment is designed around fixed cases, fixed initial alerts, fixed model settings, the same Zeek evidence interface, common report structure, and a common scoring procedure across conditions. Investigation traces are retained in `logs/` so individual runs can be audited.

The statistical pipeline is reproducible from `analysis/data/scores.csv` using `analysis/stats.py`.

## Important limitations

This repository is a **research prototype**, not a production SOC platform. The strongest conclusions are limited to the evaluated APT29 cases, the available Zeek evidence, Qwen3-4B, and the local execution environment. The study also uses a small 11-case sample and a limited rater setup for clarity evaluation. See [`LIMITATIONS.md`](LIMITATIONS.md) for the full discussion.

## Citation

If you use this repository or build on the experiment, please cite the associated research work.
