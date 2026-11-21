"""Generate fictional evidence, normalize it, apply rules and write the case report."""
from pathlib import Path
import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from incident_lab.core import normalize, correlate, evaluate, RULES
UTC = timezone.utc
DAY = datetime(2026, 3, 12, tzinfo=UTC)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8', newline='\n')


def fixtures(out):
    rng = random.Random(63127)
    rows = {'auth': [], 'endpoint': [], 'network': []}
    offsets = {'wrk-07': 95, 'wrk-12': -40, 'wrk-04': 0, 'adm-01': 95}
    counter = 0

    def emit(family, when, host, user, **fields):
        nonlocal counter
        counter += 1
        event_id = f'EV-{counter:05d}'
        record = {'id': event_id, 'host': host, 'user': user, **fields}
        if family == 'auth':
            zone = timezone(timedelta(hours=2)) if counter % 3 == 0 else UTC
            record['event_time'] = when.astimezone(zone).isoformat()
        elif family == 'endpoint':
            record['timestamp'] = (when+timedelta(seconds=offsets.get(host,0))).isoformat()
        else:
            record['epoch_ms'] = int(when.timestamp()*1000)
        rows[family].append(record)
        return event_id

    for i in range(900):
        when = DAY+timedelta(seconds=rng.randrange(86400))
        host, user = f'office-{rng.randrange(8):02d}', f'user{rng.randrange(20):02d}'
        family = rng.choices(['auth','endpoint','network'], [.65,.23,.12])[0]
        if family == 'auth':
            emit(family,when,host,user,outcome=rng.choices(['success','failure'],[.8,.2])[0],src_ip=f'10.20.0.{rng.randrange(2,150)}')
        elif family == 'endpoint':
            emit(family,when,host,user,activity='process_start',image='inventory.exe',command='inventory.exe --local-summary')
        else:
            emit(family,when,host,user,dst_ip='10.30.0.8',bytes_sent=rng.randrange(1000,50_000_000),destination='backup.internal.invalid')

    def chain(start,host,user,ip,burst=True):
        failed = []
        if burst:
            for i in range(7):
                failed.append(emit('auth',start+timedelta(seconds=i*20),host,user,outcome='failure',src_ip=ip))
        success = emit('auth',start+timedelta(seconds=180),host,user,outcome='success',src_ip=ip)
        process = emit('endpoint',start+timedelta(seconds=220),host,user,activity='process_start',image='powershell.exe',command='powershell.exe -NoProfile -EncodedCommand [synthetic-placeholder]')
        archive = emit('endpoint',start+timedelta(seconds=280),host,user,activity='file_create',path='C:/Temp/review-bundle.zip')
        transfer = emit('network',start+timedelta(seconds=360),host,user,dst_ip='198.51.100.44',bytes_sent=28_400_000,destination='transfer.example.invalid')
        return {'failures':failed,'login':success,'process':process,'archive':archive,'transfer':transfer,'host':host,'user':user}

    benign = chain(DAY+timedelta(hours=9),'adm-01','mrivera','203.0.113.55')
    attack1 = chain(DAY+timedelta(hours=10),'wrk-07','jlee','203.0.113.77')
    attack2 = chain(DAY+timedelta(hours=14),'wrk-12','ashaw','203.0.113.78')
    quiet = chain(DAY+timedelta(hours=16),'wrk-04','mchen','203.0.113.99',burst=False)
    # Confounders: shared egress IP, other host/account, and a transfer before the shell.
    for i in range(5):
        emit('auth',DAY+timedelta(hours=10,seconds=20*i),'wrk-08','jlee',outcome='failure',src_ip='203.0.113.77')
    emit('auth',DAY+timedelta(hours=10,seconds=180),'wrk-09','jlee',outcome='success',src_ip='203.0.113.77')
    emit('network',DAY+timedelta(hours=10,seconds=200),'wrk-07','jlee',dst_ip='198.51.100.44',bytes_sent=31_000_000,destination='transfer.example.invalid')
    emit('endpoint',DAY+timedelta(hours=10,seconds=240),'wrk-07','otheruser',activity='process_start',image='powershell.exe',command='powershell.exe -EncodedCommand [synthetic-placeholder]')
    emit('network',DAY+timedelta(hours=10,seconds=300),'wrk-07','otheruser',dst_ip='198.51.100.44',bytes_sent=35_000_000,destination='transfer.example.invalid')
    # Benign high-volume external backup without suspicious precursor.
    emit('network',DAY+timedelta(hours=19),'backup-01','backupsvc',dst_ip='192.0.2.33',bytes_sent=700_000_000,destination='approved-backup.example.invalid')
    for family in rows:
        rows[family] += [dict(r) for r in rows[family][:2]]
    invalid = dict(rows['auth'][0],id='BAD-TIME',event_time='2026-03-12T09:00:00')
    rows['auth'].append(invalid)
    rows['endpoint'].append(dict(rows['endpoint'][0],id='BAD-KIND',activity='unrecognized'))
    rows['network'].append(dict(rows['network'][0],id='BAD-BYTES',bytes_sent=-5))
    original = dict(rows['network'][1],id='CONFLICT-01')
    rows['network'] += [original,dict(original,bytes_sent=original['bytes_sent']+1)]
    raw = out/'data/raw';raw.mkdir(parents=True,exist_ok=True)
    for family, records in rows.items():
        rng.shuffle(records)
        text = '\n'.join(json.dumps(r,sort_keys=True) for r in records)+'\n'
        if family == 'auth':
            text += '{malformed-json\n'
        (raw/f'{family}.jsonl').write_text(text,encoding='utf-8',newline='\n')
    truth = {'scope':'Synthetic scenario labels; never supplied to the detector',
             'expected_anchors':{'R1':[attack1['login'],attack2['login']],
                                 'R2':[attack1['process'],attack2['process'],quiet['process']],
                                 'R3':[attack1['transfer'],attack2['transfer'],quiet['transfer']]},
             'cases':{'attack_burst_1':attack1,'attack_burst_2':attack2,'attack_quiet':quiet,'benign_admin':benign},
             'benign_context':'Authorized maintenance: forgotten password retries, encoded inventory script, approved archive upload. This change record is evaluation context, not detector input.',
             'quiet_context':'Stolen valid credential without a failed-login burst. R2/R3 objectives include this malicious activity, exposing the burst prerequisite blind spot.'}
    write_json(out/'data/ground_truth.json',truth)
    write_json(out/'data/clock_calibration.json',{'endpoint_offset_seconds':offsets,'uncertainty_seconds':2,
        'basis':'Known fixture clock offsets, independently configured for this exercise; not inferred from alert outcomes',
        'assumption':'Auth/network timestamps trusted; unlisted endpoint hosts have zero configured correction'})
    return truth, offsets


def build(out, generate=True):
    if generate:
        truth, offsets = fixtures(out)
    else:
        truth = json.loads((out/'data/ground_truth.json').read_text())
        offsets = json.loads((out/'data/clock_calibration.json').read_text())['endpoint_offset_seconds']
    normalized = normalize(out/'data/raw', offsets)
    alerts = correlate(normalized.events)
    metrics = evaluate(alerts,truth)
    results = out/'results';results.mkdir(exist_ok=True)
    (results/'normalized.jsonl').write_text(''.join(json.dumps(e.export(),sort_keys=True)+'\n' for e in normalized.events),encoding='utf-8',newline='\n')
    write_json(results/'alerts.json',[a.export() for a in alerts])
    write_json(results/'metrics.json',metrics)
    write_json(results/'rules.json',RULES)
    write_json(results/'quarantine.json',normalized.quarantine)
    write_json(results/'duplicates.json',normalized.duplicates)
    manifest = {'data/raw/'+p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((out/'data/raw').glob('*.jsonl'))}
    write_json(results/'source_manifest.json',manifest)
    qa = {'raw_rows':normalized.raw_rows,'normalized_events':len(normalized.events),'quarantined_rows':len(normalized.quarantine),
          'duplicate_rows_removed':len(normalized.duplicates),'alerts':len(alerts),'seed':63127,
          'clock_corrected_events':sum(e.correction_seconds != 0 for e in normalized.events),
          'conservation_check':normalized.raw_rows == len(normalized.events)+len(normalized.quarantine)+len(normalized.duplicates)}
    write_json(results/'quality_report.json',qa)
    evidence = set(e for a in alerts for e in a.evidence_ids)
    # The timeline includes every normalized event; evidence tags are a derived view.
    with (results/'timeline.csv').open('w',encoding='utf-8',newline='') as f:
        fields=['event_id','time_utc','kind','host','user','source','source_line','correction_seconds','in_alert_evidence']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for event in normalized.events:
            row=event.export();writer.writerow({k: int(event.event_id in evidence) if k=='in_alert_evidence' else row[k] for k in fields})
    render(out,normalized,alerts,metrics,truth,qa)
    print(json.dumps(qa))


def render(out,normalized,alerts,metrics,truth,qa):
    docs=out/'docs';docs.mkdir(exist_ok=True)
    events={e.event_id:e for e in normalized.events}
    target=truth['cases']['attack_burst_1']
    # Memo identifies observed facts separately from known scenario adjudication.
    memo=f'''# Incident review — synthetic exercise

## Assessment

Review host **{target['host']}**, account **{target['user']}**. A burst of failed authentication is followed by a successful login, an encoded PowerShell command, an archive creation and a large transfer. This sequence warrants investigation; the command payload and archive contents are not present in the logs, so the events alone do not establish credential theft or data exfiltration.

## Evidence chain

- Failures: {', '.join(target['failures'])}.
- Success: **{target['login']}**, {events[target['login']].time.isoformat()}.
- Process: **{target['process']}**, {events[target['process']].time.isoformat()}; endpoint clock corrected by +95 seconds (subtract 95 from recorded time).
- Archive: **{target['archive']}**. Corroborating context only; this event is not a correlation rule prerequisite.
- Transfer: **{target['transfer']}**, 28,400,000 bytes to documentation-only address 198.51.100.44.

Each event resolves to a raw source file, original line number, file SHA-256 and raw-record SHA-256 in `results/normalized.jsonl`. The timeline orders UTC event time, not arrival/file order.

## Recommended response in a real investigation

Validate account ownership and maintenance approvals first. Preserve original logs, relevant endpoint state and time-calibration records. If the sequence remains unauthorized, follow the organization's incident process to restrict the affected account/session and isolate the endpoint while coordinating with its owner. Determine what the archive contained, whether the transfer completed and whether other hosts show related activity. No containment action is executed by this offline project.

## Uncertainty

Host clocks have known fixture offsets with a stated ±2-second calibration uncertainty. Strict timestamp ordering in code does not prove causal order for events close to that uncertainty. Shared source IPs do not identify a person. An encoded command and a large transfer are dual-use indicators. There is no payload inspection, network packet capture, MFA context or session identifier in this fixture.

## Evaluation after detection

The independent synthetic ground truth labels two burst chains as malicious. One authorized administrative chain produces three false-positive alerts. A third malicious chain uses valid credentials without a failure burst and is missed by R2/R3. That blind spot follows directly from the correlation prerequisite. Do not generalize this small designed exercise's precision/recall to real deployments.

## Replay

Run `python scripts/build_case.py --replay` to reprocess the checked-in raw logs without regenerating them. Run `python -m unittest discover -s tests -v` for identity, window and provenance checks.
'''
    (docs/'incident-memo.md').write_text(memo,encoding='utf-8')
    def event_table(selected):
        rows=[]
        for event in sorted(selected,key=lambda e:(e.time,e.event_id)):
            detail=' · '.join(f'{k}={v}' for k,v in event.fields.items())
            rows.append(f'<tr><td><code>{event.event_id}</code></td><td>{event.time.strftime("%H:%M:%S")}</td><td>{html.escape(event.kind)}</td><td>{html.escape(detail)}</td><td>{event.source.split("/")[-1]}:{event.source_line}</td></tr>')
        return '<table><thead><tr><th>Evidence ID</th><th>UTC</th><th>Event</th><th>Observed fields</th><th>Source:line</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table>'
    selected=[e for e in normalized.events if e.host==target['host'] and e.user==target['user']]
    metric_rows=''.join(f'<tr><td>{m["rule"]}</td><td>{m["true_positives"]}</td><td>{m["false_positives"]}</td><td>{m["false_negatives"]}</td><td>{m["precision"]:.1%}</td><td>{m["recall"]:.1%}</td></tr>' for m in metrics)
    alert_rows=''.join(f'<tr><td>{a.rule}</td><td><code>{a.anchor_id}</code></td><td>{a.host} / {a.user}</td><td>{html.escape(a.reason)}</td></tr>' for a in alerts)
    stages=[('Authentication',target['login']),('Encoded shell',target['process']),('Archive creation',target['archive']),('External transfer',target['transfer'])]
    stage_html=''.join(f'<div class="stage"><span>{events[eid].time.strftime("%H:%M:%S")} UTC</span><h3>{label}</h3><code>{eid}</code></div>' for label,eid in stages)
    report=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Incident timeline · synthetic casefile</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#12171c;color:#dfe4e8;font:16px/1.55 system-ui,sans-serif}}header{{padding:48px 6vw 32px;border-bottom:1px solid #35404a}}h1{{font-size:54px;line-height:1.1;letter-spacing:-2px;margin:18px 0}}h2{{font-size:30px;margin:10px 0 20px;letter-spacing:-.6px}}h3{{font-size:17px;margin:12px 0}}p{{max-width:1040px}}.tag{{font:12px ui-monospace,monospace;letter-spacing:2px;color:#efbd68}}nav{{display:flex;gap:22px;margin-top:26px;font:13px ui-monospace,monospace}}a{{color:#efbd68;text-decoration:none}}main{{max-width:1340px;margin:auto;padding:0 48px}}section{{padding:45px 0;border-bottom:1px solid #35404a;scroll-margin-top:15px}}.muted{{color:#9ba8b4;font-size:14px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}.panel{{padding:22px;background:#1c242c;border:1px solid #35404a}}.flow{{display:grid;grid-template-columns:repeat(4,1fr);border-top:2px solid #c38c38;margin-top:30px}}.stage{{padding:22px 18px;border-right:1px solid #35404a}}.stage span{{color:#efbd68;font:13px ui-monospace,monospace}}.metrics{{display:flex;gap:40px;margin-top:22px}}.metric b{{font-size:38px;color:#efbd68;display:block}}.metric span{{font-size:13px;color:#9ba8b4}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{color:#efbd68;text-align:left;font:11px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.5px}}td,th{{padding:12px 10px;border-bottom:1px solid #303b45;vertical-align:top}}td:nth-child(4){{overflow-wrap:anywhere}}code,pre{{font-family:ui-monospace,Consolas,monospace}}code{{color:#e7c78e;font-size:12px}}pre{{white-space:pre-wrap;font-size:13px}}.warning{{border-left:3px solid #d49d4d;padding:12px 22px;background:#24231f;margin:22px 0}}footer{{padding:32px 0;font-size:12px;color:#9ba8b4}}@media(max-width:800px){{main{{padding:0 20px}}.grid,.flow{{grid-template-columns:1fr}}nav{{flex-wrap:wrap}}h1{{font-size:36px}}table{{font-size:11px}}.metrics{{gap:18px}}}}
</style><header id="casefile"><div class="tag">DEFENSIVE SECURITY / SYNTHETIC EXERCISE / 2026-03-12</div><h1>Incident timeline<br>evidence review</h1><p>Normalize mixed-source logs, reconstruct an event-time sequence and distinguish suspicious activity from confirmed incident ground truth.</p><div class="metrics"><div class="metric"><b>{qa['normalized_events']}</b><span>normalized events</span></div><div class="metric"><b>{qa['quarantined_rows']}</b><span>quarantined records</span></div><div class="metric"><b>{len(alerts)}</b><span>correlated alerts</span></div><div class="metric"><b>3</b><span>explicit detection rules</span></div></div><nav><a href="#timeline">Timeline</a><a href="#evidence">Evidence</a><a href="#detections">Detections</a><a href="#evaluation">Evaluation</a><a href="#decision">Response</a></nav></header><main>
<section id="timeline"><div class="tag">01 / EVENT TIME</div><h2>{target['host']} · {target['user']}</h2><p>Seven failures precede a successful login. The subsequent shell, archive and transfer form a reviewable sequence. Temporal proximity is an investigative lead, not proof of intent.</p><div class="flow">{stage_html}</div><div class="warning">Endpoint clock correction: subtract 95 seconds from recorded timestamps. Known synthetic calibration uncertainty: ±2 seconds. Auth/network clocks are trusted by exercise assumption.</div><div class="grid"><div class="panel"><h3>Preserved provenance</h3><p>Original file and line, stable event ID, original timestamp, applied correction and two SHA-256 hashes accompany every normalized event.</p></div><div class="panel"><h3>Arrival order is not event order</h3><p>Raw files are deliberately shuffled. Normalization sorts UTC event time and event ID. Same-time observations do not establish a causal predecessor.</p></div></div></section>
<section id="evidence"><div class="tag">02 / SOURCE-RESOLVABLE OBSERVATIONS</div><h2>Primary host evidence</h2>{event_table(selected)}<p class="muted">Includes a large transfer before the shell. That transfer is not retroactively attributed to a future process alert.</p></section>
<section id="detections"><div class="tag">03 / EXPLICIT CORRELATION</div><h2>Alert reasons and entity boundaries</h2><div class="grid"><div class="panel"><h3>R1 · failed-login burst</h3><p>At least five prior failures within 300 seconds, joined on host + user + source IP, followed by success.</p><h3>R2 · encoded shell</h3><p>PowerShell encoded command within 600 seconds after R1, same host and user.</p></div><div class="panel"><h3>R3 · large transfer</h3><p>At least 10,000,000 bytes to outside the configured RFC1918 boundary within 1,200 seconds after R2, same host and user.</p><p class="muted">Lower time-window bound inclusive. Predecessor must be strictly earlier. IPv4 exercise boundary is not a general Internet-routability classifier.</p></div></div><br>{'<table><thead><tr><th>Rule</th><th>Anchor</th><th>Entity</th><th>Reason</th></tr></thead><tbody>'+alert_rows+'</tbody></table>'}</section>
<section id="evaluation"><div class="tag">04 / ADJUDICATED AFTER DETECTION</div><h2>False positives and missed activity remain visible.</h2><table><thead><tr><th>Rule</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th></tr></thead><tbody>{metric_rows}</tbody></table><div class="grid" style="margin-top:24px"><div class="panel"><h3>Authorized admin activity</h3><p>A password-retry sequence, encoded maintenance script and approved upload produce three false-positive alerts. Ground-truth approval is not supplied to the detector.</p></div><div class="panel"><h3>Quiet compromise</h3><p>A valid-credential login has no failure burst. Its malicious shell and transfer are missed by R2/R3. Gating every downstream alert on R1 reduces coverage.</p></div></div><p class="muted">Metrics use rule/anchor pairs in a small designed dataset. R1 truth covers malicious burst logins; R2/R3 truth includes the quiet malicious shell/transfer. These are not population-level detection rates.</p></section>
<section id="decision"><div class="tag">05 / INVESTIGATION HANDOFF</div><h2>Preserve evidence. Validate authorization. Scope the incident.</h2><div class="grid"><div class="panel"><h3>Recommended next steps</h3><ol><li>Verify the user's maintenance/change context.</li><li>Preserve logs and endpoint evidence with hashes.</li><li>If unauthorized, follow approved account/session restriction and endpoint isolation procedures.</li><li>Confirm archive contents and transfer completion.</li><li>Search for independent shell/transfer signals outside the burst prerequisite.</li></ol></div><div class="panel"><h3>Replay this case</h3><pre>python scripts/build_case.py --replay
python -m unittest discover -s tests -v</pre><p class="muted">All processing is offline. No network requests, scans, exploitation or containment actions are performed.</p><h3>Not established by these logs</h3><p>Payload contents, data sensitivity, operator identity, MFA status and real-world business impact.</p></div></div></section><footer>AI-assisted portfolio exercise. All accounts, hosts, events and addresses are fictional. Documentation-only external IPs and .invalid domains. Actual outputs from the checked-in normalization and correlation code.</footer></main></html>'''
    from report_layout import responsive
    report = responsive(report)
    (docs/'report.html').write_text(report,encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay',action='store_true',help='Use existing raw fixtures; do not regenerate')
    parser.add_argument('--output-dir',type=Path,default=ROOT)
    args=parser.parse_args()
    build(args.output_dir.resolve(),not args.replay)
