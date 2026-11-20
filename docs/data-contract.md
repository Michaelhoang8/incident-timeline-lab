# Evidence normalization contract

## Raw source families

All records contain a nonempty `id`, `host` and `user`. IDs identify source events, not lines. Hosts and users normalize by trimming and lowercasing; the original values remain in raw files.

| File | Timestamp | Event-specific fields |
|---|---|---|
| auth.jsonl | `event_time`: ISO 8601 with required explicit offset | `outcome`: success/failure; `src_ip`: valid IP address |
| endpoint.jsonl | `timestamp`: ISO 8601 with explicit offset | `activity`: process_start/file_create; process image+command or created path |
| network.jsonl | `epoch_ms`: integer UTC epoch milliseconds | `dst_ip`: valid IP; nonnegative integer `bytes_sent`; destination label |

Booleans are rejected for integer fields. Unknown activity types, malformed JSON, ambiguous timezone-free timestamps, invalid IPs and invalid sizes are quarantined. There is no attempt to guess what a malformed record intended to mean.

## Clock calibration

`data/clock_calibration.json` supplies independently configured synthetic host offsets. An endpoint record's corrected time equals its recorded time **minus the offset**. Positive means the source clock ran ahead; negative means it ran behind. Auth/network clocks are trusted and unlisted endpoint clocks have zero correction by assumption.

The fixture declares ±2-second calibration uncertainty. The batch detector applies the central correction, but that does not prove causal order for observations close to the uncertainty. Real investigations would need corroborating synchronization records, clock-drift history and session identifiers. No clock offset is inferred from desired detection outcomes.

## Duplicate and conflict policy

Files are read in filename order and records in line order. Successfully parsed records sharing an ID are compared using sorted-key compact JSON serialization. Whitespace/key-order differences alone are exact duplicates; the first occurrence is retained and each later occurrence is logged in `results/duplicates.json`.

If the same ID has different canonical content, every valid occurrence is quarantined. Invalid records are independently quarantined during parsing. A malformed conflicting record does not replace or invalidate a separately valid parsed record; reviewers can inspect its original line in quarantine. Cross-file source IDs are assumed globally unique in this fixture.

## Provenance and outputs

Normalized events preserve `source`, `source_line`, `event_id`, `raw_time`, `correction_seconds`, `source_file_sha256` and `raw_record_sha256`. The file hash covers its complete original UTF-8 bytes. The record hash covers the original line's UTF-8 bytes **excluding the line terminator**. These detect later changes; they do not prove authenticity or establish a legal chain of custody.

Normalized records are sorted by corrected UTC time and event ID. The tie-breaker creates stable output, not a claim of causal order. The detector requires distinct event IDs. The timeline contains every accepted event, not just those selected by rules.

`results/quality_report.json` reconciles raw rows = accepted events + duplicate removals + quarantined rows. Raw files use LF line endings in Git, so byte hashes are portable across normal clones.
