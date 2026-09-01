# Results

## Overview

The evaluation compares four investigation conditions on the same 11 APT29 investigation cases: C1 (Conventional), C2 (LLM-only), C3 (LLM + Zeek), and Argus. The analysis uses paired observations because every condition investigates the same case set.

The main pattern is consistent across the experiment: **Argus produces clearer and substantially more complete investigative results than the simpler LLM + Zeek baseline, but it does so without demonstrating a runtime advantage.**

## Primary outcomes

### Investigation time

| Condition | Mean (s) | Median (s) | IQR (s) |
|---|---:|---:|---:|
| C1 | 0.063 | 0.021 | 0.097 |
| C2 | 29.586 | 29.462 | 0.768 |
| C3 | 360.357 | 357.242 | 100.053 |
| Argus | 426.774 | 519.877 | 199.475 |

The Friedman test was significant, χ²(3)=30.382, **p < 0.001**, Kendall's W=0.921. Every planned pair was significant after Holm correction except **C3 vs Argus** (adjusted p=0.2402).

Thus, the structured Argus workflow did not establish a runtime benefit over C3. The increase in time is consistent with Argus performing additional planning, evidence handling, verification, and revision steps.

### Explanation clarity

| Condition | Mean | Median | IQR |
|---|---:|---:|---:|
| C1 | 2.682 | 2.50 | 0.25 |
| C2 | 1.795 | 1.75 | 0.50 |
| C3 | 2.545 | 2.75 | 0.375 |
| **Argus** | **3.568** | **3.75** | **0.25** |

The Friedman test was significant, χ²(3)=28.038, **p < 0.001**, Kendall's W=0.850.

Argus significantly outperformed C3 (Holm-adjusted **p = 0.0059**, rank-biserial **r = -1.00**) and also outperformed C1 (**p = 0.0059**). C3 did not significantly differ from C1 (**p = 0.2148**).

This is the clearest result supporting the structured Argus report format and evidence-grounded reasoning process: the Argus reports were judged substantially easier to follow and use.

### Grounding precision

| Condition | Mean | Median | IQR |
|---|---:|---:|---:|
| **C1** | **0.859** | **0.900** | 0.050 |
| C2 | 0.768 | 0.800 | 0.175 |
| C3 | 0.714 | 0.750 | 0.150 |
| Argus | 0.841 | 0.850 | 0.075 |

The Friedman test was significant, χ²(3)=13.188, **p = 0.00425**, Kendall's W=0.400.

Argus significantly outperformed C3 (Holm-adjusted **p = 0.0234**, rank-biserial **r = -0.964**). However, Argus did **not** significantly outperform C1 (**p = 0.6406**). C1 retained the highest mean grounding precision.

This result is important: Argus improves evidence grounding relative to the unstructured tool-enabled LLM baseline, but the structured architecture cannot be claimed to outperform a deterministic investigation method on grounding precision alone.

## Secondary outcomes

### Attack-step recall

| Condition | Mean | Median | IQR |
|---|---:|---:|---:|
| C1 | 0.059 | 0.000 | 0.100 |
| C2 | 0.000 | 0.000 | 0.000 |
| C3 | 0.038 | 0.000 | 0.000 |
| **Argus** | **0.677** | **0.700** | 0.125 |

The Friedman test was significant, χ²(3)=28.731, **p < 0.001**, Kendall's W=0.871.

Argus significantly outperformed all three alternatives in the planned pairwise analysis, including C3 (**Holm-adjusted p = 0.0059**). The large increase in recall is one of the strongest empirical indications that structured investigation helps the model identify more of the attack sequence rather than stopping after isolated observations.

### Hallucination rate

| Condition | Mean | Median | IQR |
|---|---:|---:|---:|
| C1 | 0.064 | 0.000 | 0.050 |
| C2 | 0.000 | 0.000 | 0.000 |
| C3 | 0.077 | 0.000 | 0.050 |
| Argus | 0.045 | 0.000 | 0.050 |

The Friedman test was **not significant**, χ²(3)=3.625, **p = 0.305**. No pairwise tests were therefore performed for this metric.

The result does not provide evidence that the conditions differ systematically in hallucination rate in this experiment. Argus had a lower mean hallucination rate than C3, but the difference should not be interpreted as statistically established.

### Non-completion

All 44 investigations (11 cases × 4 conditions) produced a final report within the experiment limits. Consequently, non-completion was **0/11 for every condition** and Cochran's Q could not be evaluated because there was no variance in the binary outcome.

## Overall interpretation

The results support a specific claim rather than a broad claim that Argus is simply “better” in every dimension.

**What Argus improves:**

- clarity of the final investigation report.
- attack-step recall.
- grounding precision relative to C3.
- structured evidence-to-conclusion traceability.

**What Argus does not improve:**

- investigation time relative to the conventional baseline.
- statistically significant runtime compared with C3.
- grounding precision relative to C1.
- hallucination rate in a statistically demonstrated way.

The evidence therefore supports Argus as a **more structured and informative investigation workflow**, with a measurable quality cost in computation/time, rather than as a faster replacement for conventional investigation.

## Hypothesis-level conclusion

| Hypothesis | Outcome | Evidence |
|---|---|---|
| **H1 — Efficiency** | Not supported | Argus was not faster than C1 and was not significantly different from C3 in runtime |
| **H2 — Credibility** | Partially supported | Argus significantly improved grounding and recall vs C3, but not grounding vs C1 |
| **H3 — Understanding** | Supported | Argus had the highest clarity and significantly outperformed C3 |
| **H4 — Trade-off** | Supported | Better clarity/recall came with greater investigation cost |

The complete machine-readable outputs are available in `analysis/data/stats_results.json`, while the case-level scores are in `analysis/data/scores.csv`.
