"""Independent checks of the published evidence chain and its known blind spots."""
from pathlib import Path
import hashlib
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from incident_lab.core import normalize, correlate, evaluate


class CaseChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.truth=json.loads((ROOT/'data/ground_truth.json').read_text())
        offsets=json.loads((ROOT/'data/clock_calibration.json').read_text())['endpoint_offset_seconds']
        cls.normalized=normalize(ROOT/'data/raw',offsets)
        cls.alerts=correlate(cls.normalized.events)

    def test_row_accounting_and_quarantine(self):
        n=self.normalized
        self.assertEqual(n.raw_rows,959)
        self.assertEqual(len(n.events),947)
        self.assertEqual(len(n.quarantine),6)
        self.assertEqual(len(n.duplicates),6)
        self.assertEqual(n.raw_rows,len(n.events)+len(n.quarantine)+len(n.duplicates))
        self.assertFalse(any(e.event_id=='CONFLICT-01' for e in n.events))

    def test_every_event_resolves_to_unchanged_raw_evidence(self):
        manifest=json.loads((ROOT/'results/source_manifest.json').read_text())
        for path,digest in manifest.items():
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest)
        for e in self.normalized.events:
            text=(ROOT/e.source).read_text().splitlines()[e.source_line-1]
            self.assertEqual(json.loads(text)['id'],e.event_id)
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),e.raw_record_sha256)
            self.assertEqual(e.source_file_sha256,manifest[e.source])

    def test_replay_matches_published_alerts_and_metrics(self):
        actual=[a.export() for a in self.alerts]
        self.assertEqual(actual,json.loads((ROOT/'results/alerts.json').read_text()))
        self.assertEqual(evaluate(self.alerts,self.truth),json.loads((ROOT/'results/metrics.json').read_text()))

    def test_ground_truth_is_not_used_to_hide_false_positives(self):
        admin=self.truth['cases']['benign_admin']
        quiet=self.truth['cases']['attack_quiet']
        anchors={a.anchor_id for a in self.alerts}
        self.assertTrue({admin['login'],admin['process'],admin['transfer']}.issubset(anchors))
        self.assertNotIn(quiet['process'],anchors)
        self.assertNotIn(quiet['transfer'],anchors)
        self.assertEqual(len(self.alerts),9)


if __name__=='__main__':
    unittest.main()
