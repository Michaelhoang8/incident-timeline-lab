# Incident timeline lab

**[View the report in your browser](https://Michaelhoang8.github.io/incident-timeline-lab/)**

An offline defensive-security investigation built from **synthetic authentication, endpoint and network logs**. The project preserves source evidence, handles imperfect timestamps and evaluates a correlation chain against independently stored scenario labels.

The case includes two noisy malicious sequences, authorized maintenance that triggers the same rules, and a quiet valid-credential compromise the chain misses. False positives and missed activity remain visible in the published results.

## Review the case

| Artifact | What to inspect |
|---|---|
| [Incident memo](docs/incident-memo.md) | Evidence IDs, assessment, uncertainty and recommended investigation steps |
| [Casefile report](docs/report.html) | Time sequence, evidence table, correlation reasons and evaluation; open locally |
| [Screenshot gallery](docs/screenshots/README.md) | Rendered report sections for review directly on GitHub |
| [Recorded walkthrough](docs/recordings/README.md) | Browser navigation through the actual report and capture provenance |
| [Raw logs](data/raw) | Three JSONL schemas, shuffled arrival order and deliberate defects |
| [Normalized events](results/normalized.jsonl) | UTC timestamps, clock corrections, file/line provenance and hashes |
| [Timeline CSV](results/timeline.csv) | All accepted events in chronological order, with evidence membership |
| [Alerts](results/alerts.json) | Rule, anchor, complete evidence chain and explicit reason |
| [Rule metrics](results/metrics.json) | TP/FP/FN counts and the IDs behind each classification |
| [Normalization contract](docs/data-contract.md) | Schemas, identity, clock and duplicate policies |
| [Rule design](docs/rule-design.md) | Correlation prerequisites, boundaries and limitations |

## Published result

**959 raw rows → 947 normalized events, 6 duplicate removals and 6 quarantined rows.** Three rules produce nine alerts.

| Rule | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| R1: success after failure burst | 2 | 1 | 0 | 66.7% | 100% |
| R2: encoded shell after R1 | 2 | 1 | 1 | 66.7% | 66.7% |
| R3: large transfer after R2 | 2 | 1 | 1 | 66.7% | 66.7% |

These are **exercise-specific rule/anchor metrics**, not estimated real-world detection rates. R1 labels malicious burst logins; R2/R3 labels also include the quiet compromise's malicious shell and transfer, exposing the gating prerequisite's blind spot.

## Run and replay

Python 3.11+; standard library only. Python 3.13 is used in CI. Run from the repository root:

```sh
python scripts/build_case.py --replay
python -m unittest discover -s tests -v
```

Replay reads the committed raw logs and calibration, re-normalizes events and replaces generated results/report files. It does not generate replacement source logs. To regenerate the seeded exercise:

```sh
python scripts/build_case.py
```

To produce a separate copy without changing the published fixtures:

```sh
python scripts/build_case.py --output-dir build/reproduced
```

No network access, scans, exploitation or containment actions are performed. The project analyzes local files only. Optional browser capture tools are separate from the core analysis.

## Engineering details

- Authentication ISO timestamps with mixed explicit offsets, endpoint timestamps with known host clock drift, and network epoch milliseconds normalize to UTC.
- Every accepted event carries a source file, original line, event ID, original timestamp, applied correction, complete source-file SHA-256 and record SHA-256.
- Canonically identical duplicate records collapse to the first occurrence; conflicting IDs quarantine every valid occurrence rather than silently overwriting evidence.
- Correlation keys include host and account; the failure-burst key also includes source IP. Shared-IP events cannot alone connect different hosts or users.
- Time windows include their oldest allowed boundary but require strictly earlier predecessors. Equal timestamps do not establish causality.
- The detector receives no ground-truth classifications. Evaluation happens afterward, with false-positive and false-negative anchor lists committed.
- Eleven tests cover exact window/size boundaries, time ties, future-event leakage, entity isolation, clock corrections, ordering, duplicates, normalization, provenance and published-output reconciliation.

## Provenance and limits

This is an **AI-assisted portfolio exercise using entirely fictional data**. External addresses use documentation ranges and hostnames end in `.invalid`. Encoded commands contain placeholders, not executable payloads. The timestamps describe a fictional case on 2026-03-12; they are not evidence of activity on the author's or any employer's systems.

The correlation engine is a small batch implementation, not a production SIEM. Its windows, thresholds, trusted clocks and account/host attribution are explicit exercise assumptions. Results do not establish payload contents, intent, stolen data or business impact.
