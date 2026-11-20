# Correlation and evaluation

## Rule definitions

**R1 — Success after failed-login burst.** At a successful authentication anchor, select failures with matching normalized `(host, user, src_ip)` and `0 < success_time - failure_time <= 300 seconds`. At least five distinct normalized events must match. Evidence includes all matching failures and the success.

**R2 — Encoded shell after burst login.** The image basename must be `powershell.exe` or `pwsh.exe`, and the command must contain the standalone case-insensitive token `-EncodedCommand`. Select the latest prior R1 alert for the same `(host, user)` with `0 < process_time - login_time <= 600 seconds`. Evidence inherits R1's chain and adds the process.

**R3 — Large external transfer after shell.** A network event must have at least 10,000,000 bytes sent and an IPv4 destination outside the configured RFC1918 networks. Select the latest prior R2 alert for the same `(host, user)` with `0 < transfer_time - process_time <= 1,200 seconds`. Evidence inherits R2's chain and adds the transfer.

This exercise's “external” classifier means outside 10/8, 172.16/12 and 192.168/16. It is **not** a general Internet-reachability classifier; documentation IP ranges are deliberately outside the configured internal boundary. IPv6 external transfers are not detected. The command rule deliberately covers one exact flag spelling, not every equivalent PowerShell invocation.

## Identity and ordering

Each rule/anchor pair produces at most one alert. Alert IDs derive from the rule and anchor ID. Events are processed in corrected event-time order, not file order. Strictly positive deltas prevent timestamp ties or future events from establishing prerequisites. R2/R3 never join on source IP alone. No account aliasing, session resolution, reassignment or NAT attribution is inferred.

A future shell cannot retroactively explain an earlier transfer. A second host's failures cannot support the first host's login. A different user on the same host cannot inherit another user's shell alert. Tests exercise each boundary with near-identical inputs.

## Evaluation without ground-truth leakage

`correlate(events)` accepts only normalized events. `evaluate(alerts, truth)` is a separate post-processing function. Ground truth includes known malicious anchors, approved administrative context and a quiet valid-credential case.

Precision = TP / (TP + FP). Recall = TP / (TP + FN). The unit is the **rule/anchor pair**, not unique incident, host or person. Missing denominators produce null rather than a fictitious 100% rate.

R1's labeled objective is malicious burst-logon detection. R2/R3's labels cover malicious encoded-shell and large-transfer anchors, including the quiet compromise. That makes the burst prerequisite's downstream coverage loss visible. The metrics intentionally include a benign admin chain as false positives; the evaluation context is not used as an allowlist to improve the published score.

Three alerts for one chain are not three independent compromises. The sample is too small and deliberately constructed to estimate deployment performance, class balance, alert fatigue or operational precision. Tuning thresholds on this fixture would overfit the demonstration.

## Performance and next work

This is a batch educational implementation. It retains prior candidates in memory and scans entity histories, which is appropriate for the small fixture but can become quadratic for a busy entity. A production stream processor would require bounded indexes/windows, late-arrival policy, checkpointing, backpressure, retention controls and an operational account/host identity model.

Useful next detection work would add independently evaluated shell/transfer signals so that every path does not depend on R1. That change should be assessed against new held-out scenarios, not claimed to solve the issue merely by fitting this dataset.
