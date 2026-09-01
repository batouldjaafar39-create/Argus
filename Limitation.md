# Limitations

Argus is a research prototype evaluated under a controlled experimental setup. The results should therefore be interpreted as evidence for the behavior of the tested architecture under the specified conditions, not as proof that Argus is ready for production SOC deployment.

## 1. Small number of investigation cases

The experiment contains only **11 paired investigation cases**. Although the paired design improves statistical efficiency by comparing every condition on the same cases, the small sample limits statistical power and makes the results sensitive to individual scenarios. The findings should not be generalized to the full diversity of enterprise SOC incidents without additional experiments.

## 2. Single attack family and dataset

The evaluation is based on the **OTRF APT29 Detection Hackathon dataset** and the associated APT29 adversary emulation. This provides controlled ground truth, but it represents one attack family and one telemetry environment. Real SOC workloads include different adversaries, benign activity, incomplete telemetry, configuration differences, cloud-native data, endpoint telemetry, authentication events, and organization-specific logging.

A stronger validation would reproduce the experiment across multiple datasets, adversary behaviors, organizations, telemetry sources, and attack types.

## 3. Zeek-centric evidence interface

The tool-enabled conditions operate through a standardized Zeek interface. This improves experimental control, but it also limits the system's view of an incident. A production investigator may correlate endpoint detection and response data, identity logs, email telemetry, cloud audit records, SIEM events, threat intelligence, malware analysis, and other sources.

Therefore, the current results primarily demonstrate structured reasoning over the **available Zeek evidence**, not complete multimodal SOC investigation.

## 4. Small local language model

The LLM-based conditions use **Qwen3-4B-GGUF (Q4_K_M)**. The model was chosen to keep the experiment reproducible on a local 16 GB RAM environment, but it is substantially smaller than many frontier proprietary models used in recent SOC research.

Model capability is therefore a confounding practical boundary: some failures may reflect the limitations of a small local model rather than limitations inherent to the Argus workflow. Conversely, a stronger model could change both investigation quality and latency.

Future evaluation should test multiple model sizes and families while keeping the workflow fixed.

## 5. Runtime is an experimental outcome, not analyst time

The time metric measures system execution from the alert to the final report. It does **not** measure the amount of human analyst time that would be required to reproduce the same investigation manually.

This distinction matters because C1 is a deterministic software baseline. Its extremely small measured execution time does not represent the wall-clock time a human SOC analyst would need to inspect and interpret the evidence.

Consequently, the current H1 result should be interpreted as: **Argus did not outperform the implemented computational baseline in execution time**, not as evidence that Argus necessarily takes longer than a human analyst.

A more realistic efficiency study would measure analyst task time, number of manual interactions, workload, or time-to-correct-conclusion in a controlled human study.

## 6. Limited human-rater panel

Clarity was scored using a small rater setup because a professional SOC analyst panel was not available. The research design uses two raters where possible and permits a reduced second-rater sample when necessary, with inter-rater agreement checked on an overlapping subset.

This is practical for a student research project but limits the strength of claims about analyst usability. The researcher is also involved in the evaluation, which introduces potential evaluator bias even though the reports are anonymized and presented in randomized order.

A stronger study would use a larger pool of independent SOC analysts who are blinded to the system condition.

## 7. Credibility scoring depends on manual claim decomposition

Grounding precision, attack-step recall, and hallucination rate are derived from claim-level analysis. Reports are manually decomposed into atomic claims before they are checked against telemetry and the APT29 emulation plan.

This creates a possible source of evaluator subjectivity. Different decompositions can produce different claim counts, and therefore different precision or hallucination rates. The study mitigates this with fixed rules and an independent check on a sample of claims, but full independent double-coding of every claim is not performed.

## 8. No production-scale deployment

The experiment runs on a controlled local environment rather than a live SOC. It therefore does not test sustained throughput, concurrent investigations, alert bursts, operational integrations, access-control boundaries, service failures, or the economic cost of running the system continuously.

Production deployment would also introduce security concerns around tool permissions, prompt injection, malicious log content, data exfiltration, and manipulation of evidence presented to the agent.

## Scope of the conclusions

The strongest defensible conclusion from this study is that, **within this controlled 11-case APT29 experiment, the structured Argus workflow substantially improved report clarity and attack-step recall and improved grounding relative to the C3 LLM+Zeek baseline, while introducing additional investigation cost and without demonstrating a runtime advantage.**

The study does **not** establish that Argus is universally faster, more accurate, or more reliable than conventional SOC investigation; nor does it establish production readiness or generalization to other datasets and environments.

## Recommended future work

The most important next steps are a larger multi-dataset evaluation, ablation studies of the Argus components, evaluation with multiple LLMs, a larger independent analyst panel, direct measurement of human investigation time, and testing under noisy/incomplete telemetry and adversarial conditions.
