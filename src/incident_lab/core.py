"""Defensive correlation with explicit identity keys and UTC time windows."""
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

UTC = timezone.utc
RULES = {
    'R1': {'name': 'Success after failed-login burst', 'window_seconds': 300, 'minimum_failures': 5},
    'R2': {'name': 'Encoded shell after burst login', 'window_seconds': 600},
    'R3': {'name': 'Large external transfer after encoded shell', 'window_seconds': 1200, 'minimum_bytes': 10_000_000},
}
PRIVATE = tuple(ipaddress.ip_network(s) for s in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])


def utc_time(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must be an ISO string with an explicit offset')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Naive timestamp has no unambiguous timezone')
    return result.astimezone(UTC)


@dataclass(frozen=True)
class Event:
    event_id: str
    time: datetime
    kind: str
    host: str
    user: str
    source: str
    source_line: int
    raw_time: str
    correction_seconds: int
    fields: dict
    source_file_sha256: str = ''
    raw_record_sha256: str = ''

    def export(self):
        return {'event_id': self.event_id, 'time_utc': self.time.isoformat(), 'kind': self.kind,
                'host': self.host, 'user': self.user, 'source': self.source,
                'source_line': self.source_line, 'raw_time': self.raw_time,
                'correction_seconds': self.correction_seconds,
                'source_file_sha256': self.source_file_sha256,
                'raw_record_sha256': self.raw_record_sha256, **self.fields}


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule: str
    time: datetime
    host: str
    user: str
    anchor_id: str
    evidence_ids: tuple[str, ...]
    reason: str

    def export(self):
        return {'alert_id': self.alert_id, 'rule': self.rule, 'rule_name': RULES[self.rule]['name'],
                'time_utc': self.time.isoformat(), 'host': self.host, 'user': self.user,
                'anchor_id': self.anchor_id, 'evidence_ids': list(self.evidence_ids), 'reason': self.reason}


@dataclass(frozen=True)
class Normalization:
    events: tuple[Event, ...]
    quarantine: tuple[dict, ...]
    duplicates: tuple[dict, ...]
    raw_rows: int


def _text(record, field):
    value = record[field]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{field} must be a nonempty string')
    return value.strip()


def _event(record, family, source, line, offsets):
    event_id = _text(record, 'id')
    host = _text(record, 'host').lower()
    user = _text(record, 'user').lower()
    correction = 0
    if family == 'auth':
        raw_time = _text(record, 'event_time')
        when = utc_time(raw_time)
        outcome = _text(record, 'outcome')
        if outcome not in ('failure', 'success'):
            raise ValueError('Unknown authentication outcome')
        address = str(ipaddress.ip_address(_text(record, 'src_ip')))
        kind, fields = 'auth.'+outcome, {'src_ip': address}
    elif family == 'endpoint':
        raw_time = _text(record, 'timestamp')
        correction = offsets.get(host, 0)
        if type(correction) is not int:
            raise ValueError('Clock calibration offset must be integer seconds')
        when = utc_time(raw_time) - timedelta(seconds=correction)
        activity = _text(record, 'activity')
        if activity == 'process_start':
            kind = 'process.start'
            fields = {'image': _text(record, 'image').lower(), 'command': _text(record, 'command')}
        elif activity == 'file_create':
            kind, fields = 'file.create', {'path': _text(record, 'path')}
        else:
            raise ValueError('Unknown endpoint activity')
    elif family == 'network':
        epoch = record['epoch_ms']
        if type(epoch) is not int:
            raise ValueError('epoch_ms must be an integer')
        when = datetime.fromtimestamp(epoch/1000, UTC)
        raw_time = str(epoch)
        count = record['bytes_sent']
        if type(count) is not int or count < 0:
            raise ValueError('bytes_sent must be a nonnegative integer')
        address = str(ipaddress.ip_address(_text(record, 'dst_ip')))
        kind, fields = 'network.transfer', {'dst_ip': address, 'bytes_sent': count,
                                            'destination': _text(record, 'destination')}
    else:
        raise ValueError('Unknown log family')
    return Event(event_id, when, kind, host, user, source, line, raw_time, correction, fields)


def normalize(raw_dir: Path, clock_offsets: dict[str, int] | None = None) -> Normalization:
    """Normalize JSONL, quarantine invalid/conflicting IDs, keep exact duplicates once.

    The first occurrence of a byte-equivalent JSON record after canonical JSON
    encoding is retained. A conflicting ID quarantines every valid occurrence;
    no arbitrary last-write-wins rule can overwrite evidence.
    """
    candidates = defaultdict(list)
    quarantine, duplicates = [], []
    count = 0
    for path in sorted(raw_dir.glob('*.jsonl')):
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        for line, text in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            count += 1
            provenance = {'source': 'data/raw/'+path.name, 'source_line': line}
            try:
                record = json.loads(text)
                if not isinstance(record, dict):
                    raise ValueError('Record must be an object')
                event = _event(record, path.stem, provenance['source'], line, clock_offsets or {})
                event = replace(event, source_file_sha256=file_hash,
                                raw_record_sha256=hashlib.sha256(text.encode('utf-8')).hexdigest())
                canonical = json.dumps(record, sort_keys=True, separators=(',', ':'))
                candidates[event.event_id].append((event, canonical))
            except (ValueError, KeyError, TypeError, OverflowError, OSError) as exc:
                quarantine.append({**provenance, 'reason': str(exc), 'raw': text})
    accepted = []
    for event_id, records in sorted(candidates.items()):
        if len(set(raw for _, raw in records)) > 1:
            for event, raw in records:
                quarantine.append({'source': event.source, 'source_line': event.source_line,
                                   'event_id': event_id, 'reason': 'Conflicting duplicate ID', 'raw': raw})
            continue
        accepted.append(records[0][0])
        for event, _ in records[1:]:
            duplicates.append({'event_id': event_id, 'source': event.source,
                               'source_line': event.source_line, 'retained_source': records[0][0].source,
                               'retained_line': records[0][0].source_line})
    accepted.sort(key=lambda e: (e.time, e.event_id))
    return Normalization(tuple(accepted), tuple(quarantine), tuple(duplicates), count)


def _alert(rule, anchor, evidence, reason):
    digest = hashlib.sha256(f'{rule}:{anchor.event_id}'.encode()).hexdigest()[:12]
    unique = tuple(dict.fromkeys(evidence))
    return Alert('A-'+digest, rule, anchor.time, anchor.host, anchor.user,
                 anchor.event_id, unique, reason)


def _external(address):
    """Exercise boundary: outside configured RFC1918 space, not Internet routability.

    Fixtures use documentation-only external addresses. ipaddress.is_global would
    intentionally classify those as nonglobal and is unsuitable for this model.
    """
    ip = ipaddress.ip_address(address)
    return ip.version == 4 and not any(ip in net for net in PRIVATE)


def correlate(events) -> tuple[Alert, ...]:
    """Process event time deterministically; entity joins never use host alone.

    Lower window bounds are inclusive, upper bounds require strictly earlier
    evidence. Events sharing a timestamp do not establish causal order. An anchor
    creates at most one alert per rule, with the latest eligible predecessor.
    """
    ordered = sorted(events, key=lambda e: (e.time, e.event_id))
    if len({e.event_id for e in ordered}) != len(ordered):
        raise ValueError('Correlation requires unique normalized event IDs')
    failures = defaultdict(list)
    logins = defaultdict(list)
    shells = defaultdict(list)
    alerts = []
    for event in ordered:
        entity = event.host, event.user
        if event.kind == 'auth.failure':
            failures[(*entity, event.fields['src_ip'])].append(event)
        elif event.kind == 'auth.success':
            earlier = [e for e in failures[(*entity, event.fields['src_ip'])]
                       if 0 < (event.time-e.time).total_seconds() <= RULES['R1']['window_seconds']]
            if len(earlier) >= RULES['R1']['minimum_failures']:
                alert = _alert('R1', event, [e.event_id for e in earlier]+[event.event_id],
                               f'{len(earlier)} failures then success for identical host/user/source IP within 300 seconds')
                alerts.append(alert);logins[entity].append(alert)
        elif event.kind == 'process.start':
            image = event.fields['image'].replace('\\', '/').split('/')[-1]
            encoded = '-encodedcommand' in event.fields['command'].lower().split()
            if image not in ('powershell.exe', 'pwsh.exe') or not encoded:
                continue
            earlier = [a for a in logins[entity] if 0 < (event.time-a.time).total_seconds() <= RULES['R2']['window_seconds']]
            if earlier:
                predecessor = earlier[-1]
                alert = _alert('R2', event, list(predecessor.evidence_ids)+[event.event_id],
                               f'Encoded PowerShell observed {(event.time-predecessor.time).total_seconds():.0f}s after burst login; same host and user')
                alerts.append(alert);shells[entity].append(alert)
        elif event.kind == 'network.transfer':
            if event.fields['bytes_sent'] < RULES['R3']['minimum_bytes'] or not _external(event.fields['dst_ip']):
                continue
            earlier = [a for a in shells[entity] if 0 < (event.time-a.time).total_seconds() <= RULES['R3']['window_seconds']]
            if earlier:
                predecessor = earlier[-1]
                alert = _alert('R3', event, list(predecessor.evidence_ids)+[event.event_id],
                               f"{event.fields['bytes_sent']:,} bytes to outside-RFC1918 address {(event.time-predecessor.time).total_seconds():.0f}s after correlated shell")
                alerts.append(alert)
    return tuple(alerts)


def evaluate(alerts, truth):
    """Evaluate rule/anchor pairs; truth is never used by normalization/correlation."""
    result = []
    for rule in RULES:
        expected = set(truth['expected_anchors'][rule])
        actual = {a.anchor_id for a in alerts if a.rule == rule}
        tp, fp, fn = actual & expected, actual-expected, expected-actual
        result.append({'rule': rule, 'true_positives': len(tp), 'false_positives': len(fp),
                       'false_negatives': len(fn), 'precision': len(tp)/len(actual) if actual else None,
                       'recall': len(tp)/len(expected) if expected else None,
                       'true_positive_ids': sorted(tp), 'false_positive_ids': sorted(fp),
                       'false_negative_ids': sorted(fn)})
    return result
