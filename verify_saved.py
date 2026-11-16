"""Независимый повторный расчёт сохранённых данных, без повторения бенчмарка."""
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path

r=Path(__file__).parent/'results'
raw=list(csv.DictReader((r/'performance_raw.csv').open()))
av=list(csv.DictReader((r/'avalanche_raw.csv').open()))
summary=list(csv.DictReader((r/'performance_summary.csv').open()))
av_summary=list(csv.DictReader((r/'avalanche_summary.csv').open()))
assert len(raw)==900 and len(av)==18000
for row in raw:
    assert math.isclose(float(row['elapsed_ns'])/int(row['iterations']),float(row['ns_per_hash']),rel_tol=1e-12)
for row in summary:
    vals=[float(v['ns_per_hash']) for v in raw if v['algorithm']==row['algorithm'] and v['size_bytes']==row['size_bytes']]
    assert len(vals)==15
    q=statistics.quantiles(vals,n=4,method='inclusive')
    assert statistics.median(vals)==float(row['median_ns'])
    assert q[0]==float(row['q1_ns']) and q[2]==float(row['q3_ns'])
corpus={}
for line in (r/'corpus.jsonl').read_text().splitlines():
    d=json.loads(line);corpus[d['size'],d['trial']]=d
assert len(corpus)==3000
for row in av:
    d=corpus[int(row['size_bytes']),int(row['trial'])]
    a=bytes.fromhex(d['message']);b=bytearray(a);b[d['bit']//8]^=1<<(d['bit']%8)
    assert (int.from_bytes(a,'big')^int.from_bytes(b,'big')).bit_count()==1
    h1=hashlib.new(row['algorithm'],a,usedforsecurity=False).digest()
    h2=hashlib.new(row['algorithm'],b,usedforsecurity=False).digest()
    # Независимый способ подсчёта: XOR двух целых вместо цикла по байтам.
    distance=(int.from_bytes(h1,'big')^int.from_bytes(h2,'big')).bit_count()
    assert distance==int(row['hamming'])
    assert 100*distance/(8*len(h1))==float(row['percent'])
for row in av_summary:
    vals=[float(v['percent']) for v in av if v['algorithm']==row['algorithm'] and v['size_bytes']==row['size_bytes']]
    assert len(vals)==1000
    assert statistics.mean(vals)==float(row['mean_percent'])
    assert statistics.stdev(vals)==float(row['sd_percent'])
for file,expected in json.loads((r/'source_sha256.json').read_text()).items():
    assert hashlib.sha256((r.parent/file).read_bytes()).hexdigest()==expected
report=dict(performance_rows=len(raw),avalanche_rows=len(av),corpus_pairs=len(corpus),
            recalculated_avalanche_rows=len(av),summary_match=True,source_hashes_match=True,
            note='Это повторный расчёт данных и проверка сохранённых файлов, не независимая экспертиза криптостойкости.')
(r/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
print(json.dumps(report,ensure_ascii=False,indent=2))
