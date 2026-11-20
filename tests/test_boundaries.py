"""Independent time-window, attribution and normalization boundary checks."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from incident_lab.core import Event, correlate, normalize

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)

def event(identifier, seconds, kind, host='a', user='alice', **fields):
    return Event(identifier, BASE + timedelta(seconds=seconds), kind, host, user,
                 'fixture', 1, 'fixture', 0, fields)

def failures():
    return [event(f'f{i}', -300+i, 'auth.failure', src_ip='192.0.2.1') for i in range(5)]

def login(seconds=0, **kw):
    return event('success', seconds, 'auth.success', src_ip='192.0.2.1', **kw)

def shell(seconds=600, **kw):
    return event('shell', seconds, 'process.start', image='powershell.exe',
                 command='powershell.exe -EncodedCommand fixture', **kw)

def transfer(seconds=1800, **kw):
    return event('transfer', seconds, 'network.transfer', dst_ip='203.0.113.1',
                 bytes_sent=10_000_000, destination='fixture', **kw)

class BoundaryChecks(unittest.TestCase):
    def rules(self, events):
        return [alert.rule for alert in correlate(events)]

    def test_all_window_lower_bounds_and_thresholds_are_inclusive(self):
        self.assertEqual(self.rules(failures()+[login(),shell(),transfer()]), ['R1','R2','R3'])
        self.assertEqual(self.rules(failures()+[login(.001)]), [])
        self.assertEqual(self.rules(failures()+[login(),shell(600.001)]), ['R1'])
        self.assertEqual(self.rules(failures()+[login(),shell(),transfer(1800.001)]), ['R1','R2'])

    def test_equal_or_future_events_do_not_imply_causality(self):
        fs=[event(f'f{i}', 0, 'auth.failure', src_ip='192.0.2.1') for i in range(5)]
        self.assertEqual(self.rules(fs+[login()]), [])
        self.assertEqual(self.rules(failures()+[login(),shell(0)]), ['R1'])
        self.assertEqual(self.rules(failures()+[login(),shell(),transfer(600)]), ['R1','R2'])
        self.assertEqual(self.rules(failures()+[login(),shell(-1),transfer(-2)]), ['R1'])

    def test_cross_entity_events_are_never_attributed(self):
        for change in [{'host':'b'}, {'user':'bob'}]:
            self.assertEqual(self.rules(failures()+[login(**change)]), [])
            self.assertEqual(self.rules(failures()+[login(),shell(**change)]), ['R1'])
            self.assertEqual(self.rules(failures()+[login(),shell(),transfer(**change)]), ['R1','R2'])
        different_ip=event('s',0,'auth.success',src_ip='192.0.2.2')
        self.assertEqual(self.rules(failures()+[different_ip]), [])

    def test_input_order_does_not_change_evidence_and_duplicates_are_rejected(self):
        events=failures()+[login(),shell(),transfer()]
        self.assertEqual(correlate(events),correlate(reversed(events)))
        self.assertEqual(correlate(events)[-1].evidence_ids,tuple(e.event_id for e in events))
        with self.assertRaises(ValueError): correlate(events+[events[0]])

    def test_transfer_threshold_and_internal_boundary(self):
        for address, amount in [('203.0.113.1',9_999_999),('10.0.0.1',10_000_000),
                                ('172.16.0.1',10_000_000),('192.168.1.1',10_000_000)]:
            candidate=event('transfer',700,'network.transfer',dst_ip=address,
                            bytes_sent=amount,destination='fixture')
            self.assertEqual(self.rules(failures()+[login(),shell(),candidate]),['R1','R2'])

    def test_positive_and_negative_clock_offsets_use_same_utc_reference(self):
        rows=[]
        for name,offset in [('ahead',95),('behind',-40)]:
            rows.append({'id':name,'host':name,'user':'alice',
                         'timestamp':(BASE+timedelta(seconds=offset)).isoformat(),
                         'activity':'file_create','path':'C:/Temp/example.zip'})
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            (p/'endpoint.jsonl').write_text('\n'.join(json.dumps(r) for r in rows),encoding='utf-8')
            result=normalize(p,{'ahead':95,'behind':-40})
        self.assertEqual(len(result.events),2)
        self.assertTrue(all(e.time==BASE for e in result.events))
        self.assertEqual({e.correction_seconds for e in result.events},{95,-40})

    def test_normalization_deduplicates_canonical_json_and_quarantines_conflicts(self):
        valid={'id':'one','host':' A ','user':'ALICE','event_time':'2026-01-01T01:00:00+01:00','outcome':'failure','src_ip':'192.0.2.1'}
        conflict=dict(valid,id='conflict')
        rows=[json.dumps(valid),json.dumps(valid,sort_keys=True),json.dumps(conflict),json.dumps(dict(conflict,outcome='success'))]
        rows += [json.dumps(dict(valid,id='naive',event_time='2026-01-01T00:00:00')), '{broken']
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'auth.jsonl').write_text('\n'.join(rows),encoding='utf-8')
            result=normalize(p)
        self.assertEqual(result.raw_rows,6)
        self.assertEqual(len(result.events),1)
        self.assertEqual(len(result.duplicates),1)
        self.assertEqual(len(result.quarantine),4)
        self.assertEqual((result.events[0].host,result.events[0].user,result.events[0].time),('a','alice',BASE))
        self.assertEqual(len(result.events[0].source_file_sha256),64)

if __name__ == '__main__': unittest.main()
