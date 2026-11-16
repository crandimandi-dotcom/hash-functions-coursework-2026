"""Независимый повторный расчёт сохранённых данных, без повторения бенчмарка."""
import csv
from collections import Counter
import hashlib
import json
import math
import statistics
from pathlib import Path
r = Path(__file__).parent / 'results'
raw = list(csv.DictReader((r / 'performance_raw.csv').open()))
av = list(csv.DictReader((r / 'avalanche_raw.csv').open()))
summary = list(csv.DictReader((r / 'performance_summary.csv').open()))
av_summary = list(csv.DictReader((r / 'avalanche_summary.csv').open()))
if not (len(raw) == 900 and len(av) == 18000):
    raise ValueError('Проверка данных не пройдена: len(raw) == 900 and len(av) == 18000')
config = json.loads((r / 'config.json').read_text())
algorithms = config['algorithms']
sizes = config['sizes']
expected_groups = {(a, str(n)) for a in algorithms for n in sizes}
if Counter((x['algorithm'], x['size_bytes']) for x in raw) != Counter({k: 15 for k in expected_groups}):
    raise ValueError('Неполный набор серий производительности')
if Counter((x['algorithm'], x['size_bytes']) for x in summary) != Counter({k: 1 for k in expected_groups}):
    raise ValueError('Неполный набор сводных строк производительности')
if len({(x['algorithm'], x['size_bytes'], x['repeat']) for x in raw}) != 900:
    raise ValueError('Повтор идентификатора серии')
expected_av = {(a, str(n)) for a in algorithms for n in (16, 64, 1024)}
if Counter((x['algorithm'], x['size_bytes']) for x in av) != Counter({k: 1000 for k in expected_av}):
    raise ValueError('Неполный набор лавинных испытаний')
if Counter((x['algorithm'], x['size_bytes']) for x in av_summary) != Counter({k: 1 for k in expected_av}):
    raise ValueError('Неполный набор сводных лавинных строк')
if len({(x['algorithm'], x['size_bytes'], x['trial']) for x in av}) != 18000:
    raise ValueError('Повтор идентификатора лавинного испытания')
for row in raw + summary:
    timing = float(row.get('ns_per_hash', row.get('median_ns')))
    rate = int(row['size_bytes']) / 2**20 / (timing / 1e9)
    if timing <= 0 or not math.isclose(rate, float(row['mib_per_s']), rel_tol=1e-12):
        raise ValueError('Неверное время или скорость MiB/s')
for row in raw:
    if not math.isclose(float(row['elapsed_ns']) / int(row['iterations']), float(row['ns_per_hash']), rel_tol=1e-12):
        raise ValueError("Проверка данных не пройдена: math.isclose(float(row['elapsed_ns']) / int(row['iterations']), float(row['ns_per_hash']), rel_tol=1e-12)")
for row in summary:
    vals = [float(v['ns_per_hash']) for v in raw if v['algorithm'] == row['algorithm'] and v['size_bytes'] == row['size_bytes']]
    if not len(vals) == 15:
        raise ValueError('Проверка данных не пройдена: len(vals) == 15')
    q = statistics.quantiles(vals, n=4, method='inclusive')
    if not statistics.median(vals) == float(row['median_ns']):
        raise ValueError("Проверка данных не пройдена: statistics.median(vals) == float(row['median_ns'])")
    if not (q[0] == float(row['q1_ns']) and q[2] == float(row['q3_ns'])):
        raise ValueError("Проверка данных не пройдена: q[0] == float(row['q1_ns']) and q[2] == float(row['q3_ns'])")
corpus = {}
for line in (r / 'corpus.jsonl').read_text().splitlines():
    d = json.loads(line)
    corpus[d['size'], d['trial']] = d
if not len(corpus) == 3000:
    raise ValueError('Проверка данных не пройдена: len(corpus) == 3000')
for row in av:
    d = corpus[int(row['size_bytes']), int(row['trial'])]
    a = bytes.fromhex(d['message'])
    b = bytearray(a)
    b[d['bit'] // 8] ^= 1 << d['bit'] % 8
    if not (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).bit_count() == 1:
        raise ValueError("Проверка данных не пройдена: (int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).bit_count() == 1")
    h1 = hashlib.new(row['algorithm'], a, usedforsecurity=False).digest()
    h2 = hashlib.new(row['algorithm'], b, usedforsecurity=False).digest()
    distance = (int.from_bytes(h1, 'big') ^ int.from_bytes(h2, 'big')).bit_count()
    if int(row['changed_bit']) != d['bit'] or int(row['output_bits']) != 8 * len(h1):
        raise ValueError('Неверный индекс изменённого бита или длина хеша')
    if not distance == int(row['hamming']):
        raise ValueError("Проверка данных не пройдена: distance == int(row['hamming'])")
    if not 100 * distance / (8 * len(h1)) == float(row['percent']):
        raise ValueError("Проверка данных не пройдена: 100 * distance / (8 * len(h1)) == float(row['percent'])")
for row in av_summary:
    vals = [float(v['percent']) for v in av if v['algorithm'] == row['algorithm'] and v['size_bytes'] == row['size_bytes']]
    if int(row['n']) != len(vals) or min(vals) != float(row['min_percent']) or max(vals) != float(row['max_percent']):
        raise ValueError('Неверные n/min/max в лавинной сводке')
    if not len(vals) == 1000:
        raise ValueError('Проверка данных не пройдена: len(vals) == 1000')
    if not statistics.mean(vals) == float(row['mean_percent']):
        raise ValueError("Проверка данных не пройдена: statistics.mean(vals) == float(row['mean_percent'])")
    if not statistics.stdev(vals) == float(row['sd_percent']):
        raise ValueError("Проверка данных не пройдена: statistics.stdev(vals) == float(row['sd_percent'])")
revisions=json.loads((r.parent/'provenance/source_changes.json').read_text()) if (r.parent/'provenance/source_changes.json').exists() else {}
for file, expected in json.loads((r/'source_sha256.json').read_text()).items():
    current=hashlib.sha256((r.parent/file).read_bytes()).hexdigest()
    if current == expected: continue
    revision=revisions.get(file)
    if not revision or revision['original_sha256'] != expected or revision['current_sha256'] != current:
        raise ValueError('Необъяснённое изменение исходника: '+file)
    original=r.parent/'provenance'/revision['original_file']
    if hashlib.sha256(original.read_bytes()).hexdigest()!=expected:
        raise ValueError('Повреждён исходник первоначального эксперимента: '+file)
report = dict(performance_rows=len(raw), avalanche_rows=len(av), corpus_pairs=len(corpus), recalculated_avalanche_rows=len(av), summary_match=True, original_sources_verified=True, documented_revisions=list(revisions), note='Это повторный расчёт данных и проверка сохранённых файлов, не независимая экспертиза криптостойкости.')
(r / 'verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2))
