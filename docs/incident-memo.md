# Incident review — synthetic exercise

## Assessment

Review host **wrk-07**, account **jlee**. A burst of failed authentication is followed by a successful login, an encoded PowerShell command, an archive creation and a large transfer. This sequence warrants investigation; the command payload and archive contents are not present in the logs, so the events alone do not establish credential theft or data exfiltration.

## Evidence chain

- Failures: EV-00912, EV-00913, EV-00914, EV-00915, EV-00916, EV-00917, EV-00918.
- Success: **EV-00919**, 2026-03-12T10:03:00+00:00.
- Process: **EV-00920**, 2026-03-12T10:03:40+00:00; endpoint clock corrected by +95 seconds (subtract 95 from recorded time).
- Archive: **EV-00921**. Corroborating context only; this event is not a correlation rule prerequisite.
- Transfer: **EV-00922**, 28,400,000 bytes to documentation-only address 198.51.100.44.

Each event resolves to a raw source file, original line number, file SHA-256 and raw-record SHA-256 in `results/normalized.jsonl`. The timeline orders UTC event time, not arrival/file order.

## Recommended response in a real investigation

Validate account ownership and maintenance approvals first. Preserve original logs, relevant endpoint state and time-calibration records. If the sequence remains unauthorized, follow the organization's incident process to restrict the affected account/session and isolate the endpoint while coordinating with its owner. Determine what the archive contained, whether the transfer completed and whether other hosts show related activity. No containment action is executed by this offline project.

## Uncertainty

Host clocks have known fixture offsets with a stated ±2-second calibration uncertainty. Strict timestamp ordering in code does not prove causal order for events close to that uncertainty. Shared source IPs do not identify a person. An encoded command and a large transfer are dual-use indicators. There is no payload inspection, network packet capture, MFA context or session identifier in this fixture.

## Evaluation after detection

The independent synthetic ground truth labels two burst chains as malicious. One authorized administrative chain produces three false-positive alerts. A third malicious chain uses valid credentials without a failure burst and is missed by R2/R3. That blind spot follows directly from the correlation prerequisite. Do not generalize this small designed exercise's precision/recall to real deployments.

## Replay

Run `python scripts/build_case.py --replay` to reprocess the checked-in raw logs without regenerating them. Run `python -m unittest discover -s tests -v` for identity, window and provenance checks.
