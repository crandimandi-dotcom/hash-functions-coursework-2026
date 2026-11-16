"""Воспроизводимое сравнение шести хеш-функций. Python >= 3.10.
Измеряет библиотечные реализации; учебный SHA-256 тестирует отдельно.
Все измерения сохраняются, выбросы автоматически не удаляются.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import random
import ssl
import statistics as st
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from sha256_reference import sha256 as reference_sha256

ALGORITHMS = ('md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512')
SIZES = (0, 1, 16, 64, 128, 1024, 4096, 65536, 1048576, 8388608)
SEED = 20261116
# Независимые ожидаемые значения: RFC 1321, RFC 6234 и примеры NIST.
VECTORS = [
 ('md5', b'', 'd41d8cd98f00b204e9800998ecf8427e', 'RFC 1321 A.5'),
 ('md5', b'abc', '900150983cd24fb0d6963f7d28e17f72', 'RFC 1321 A.5'),
 ('sha1', b'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d', 'RFC 6234 8.5'),
 ('sha256', b'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'RFC 6234 8.5'),
 ('sha512', b'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f', 'RFC 6234 8.5'),
 ('sha3_256', b'', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', 'NIST SHA3-256_Msg0.pdf, p.37'),
 ('sha3_512', b'', 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26', 'NIST SHA3-512_Msg0.pdf, pp.37-38'),
 ('sha256', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1', 'RFC 6234 8.5'),
]
COLLISION_A = bytes.fromhex('''
d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89
55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b
d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0
e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70''')
COLLISION_B = bytes.fromhex('''
d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89
55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b
d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0
e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70''')


def digest(name, data):
    # MD5 и SHA-1 здесь применяются только для исследования.
    return hashlib.new(name, data, usedforsecurity=False).digest()


def distance(a, b):
    if len(a) != len(b):
        raise ValueError('Длины должны совпадать')
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def save_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def check():
    checks = []
    for name, data, expected, source in VECTORS:
        actual = digest(name, data).hex()
        checks.append(dict(test='external_vector', algorithm=name,
                           message_hex=data.hex(), expected=expected,
                           actual=actual, source=source, passed=actual == expected))
        if name == 'sha256':
            checks.append(dict(test='reference_external', algorithm=name,
                               length=len(data), passed=reference_sha256(data).hex() == expected))
    rng = random.Random(SEED)
    # Границы дополнения SHA-256 плюс 100 случайных длин.
    lengths = [0,1,55,56,57,63,64,65,119,120,127,128,129,1024]
    lengths += [rng.randrange(0,4097) for _ in range(100)]
    for length in lengths:
        data = rng.randbytes(length)
        checks.append(dict(test='reference_vs_library', length=length,
                           passed=reference_sha256(data) == digest('sha256', data)))
    for name in ALGORITHMS:
        for length in (0,1,55,56,63,64,65,71,72,73,111,112,127,128,135,136,137,1024):
            data = rng.randbytes(length)
            h = hashlib.new(name, usedforsecurity=False)
            for offset in range(0, length, 17):
                h.update(data[offset:offset+17])
            checks.append(dict(test='streaming', algorithm=name, length=length,
                               passed=h.digest() == digest(name, data)))
    checks.append(dict(test='hamming_known', passed=distance(b'\x00',b'\xff') == 8))
    checks.append(dict(test='hamming_identity', passed=distance(b'abc',b'abc') == 0))
    if not all(c['passed'] for c in checks):
        raise RuntimeError('Тест не пройден: ' + str([c for c in checks if not c['passed']]))
    return checks


def collision():
    # Проверка опубликованной пары, а не самостоятельный поиск.
    rows = [dict(algorithm=n, hash_a=digest(n,COLLISION_A).hex(),
                 hash_b=digest(n,COLLISION_B).hex(),
                 equal=digest(n,COLLISION_A) == digest(n,COLLISION_B))
            for n in ALGORITHMS]
    if COLLISION_A == COLLISION_B or not rows[0]['equal']:
        raise RuntimeError('Некорректная пара MD5')
    if rows[0]['hash_a'] != '79054025255fb1a26e4bc422aef54eb4':
        raise RuntimeError('Расхождение с опубликованным значением')
    return dict(source='https://www.mscs.dal.ca/~selinger/md5collision/',
                length_a=len(COLLISION_A), length_b=len(COLLISION_B),
                input_distance=distance(COLLISION_A,COLLISION_B), results=rows)


def timed(name, data, count):
    start = time.perf_counter_ns()
    for _ in range(count):
        digest(name, data)
    return time.perf_counter_ns() - start


def performance(repeats, target):
    rng = random.Random(SEED + 1)
    data_rng = random.Random(SEED)
    data = {size:data_rng.randbytes(size) for size in SIZES}
    counts = {}
    for size in SIZES:
        for name in ALGORITHMS:
            timed(name,data[size],3)  # прогрев
            count = 1
            while True:
                elapsed = timed(name,data[size],count)
                if elapsed >= target * 1e9:
                    break
                count *= 2
            counts[name,size] = count
    rows = []
    jobs = [(n,s) for n in ALGORITHMS for s in SIZES]
    for repeat in range(repeats):
        rng.shuffle(jobs)
        for order,(name,size) in enumerate(jobs):
            count = counts[name,size]
            elapsed = timed(name,data[size],count)
            ns = elapsed / count
            rows.append(dict(repeat=repeat, order=order, algorithm=name,
                             size_bytes=size, iterations=count, elapsed_ns=elapsed,
                             ns_per_hash=ns, mib_per_s=size/(ns/1e9)/2**20 if size else 0))
        print(f'Серия скорости {repeat+1}/{repeats}',flush=True)
    return rows, {str(s):digest('sha256',d).hex() for s,d in data.items()}


def avalanche(trials, out):
    rng = random.Random(SEED + 2)
    rows = []
    with (out/'corpus.jsonl').open('w',encoding='utf-8') as corpus:
        for size in (16,64,1024):
            for trial in range(trials):
                data = rng.randbytes(size)
                bit = rng.randrange(size*8)
                changed = bytearray(data)
                changed[bit//8] ^= 1 << (bit%8)
                if distance(data,changed) != 1:
                    raise RuntimeError('Изменён не один бит')
                corpus.write(json.dumps(dict(size=size,trial=trial,message=data.hex(),bit=bit))+'\n')
                for name in ALGORITHMS:
                    h1,h2 = digest(name,data),digest(name,changed)
                    d = distance(h1,h2)
                    rows.append(dict(algorithm=name,size_bytes=size,trial=trial,
                                     changed_bit=bit,hamming=d,output_bits=8*len(h1),
                                     percent=100*d/(8*len(h1))))
    return rows


def summarize(perf, avalanche_rows):
    p,a = [],[]
    for name in ALGORITHMS:
        for size in SIZES:
            vals = [r['ns_per_hash'] for r in perf if r['algorithm']==name and r['size_bytes']==size]
            q = st.quantiles(vals,n=4,method='inclusive')
            med = st.median(vals)
            p.append(dict(algorithm=name,size_bytes=size,median_ns=med,q1_ns=q[0],q3_ns=q[2],
                          mib_per_s=size/(med/1e9)/2**20 if size else 0))
        for size in (16,64,1024):
            vals = [r['percent'] for r in avalanche_rows if r['algorithm']==name and r['size_bytes']==size]
            a.append(dict(algorithm=name,size_bytes=size,n=len(vals),mean_percent=st.mean(vals),
                          sd_percent=st.stdev(vals),min_percent=min(vals),max_percent=max(vals)))
    return p,a


def environment():
    cpu = platform.processor() or 'not reported'
    if sys.platform == 'darwin':
        result = subprocess.run(['sysctl','-n','machdep.cpu.brand_string'],capture_output=True,text=True)
        if result.returncode == 0:
            cpu = result.stdout.strip()
    return dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                python=sys.version,implementation=platform.python_implementation(),
                openssl=ssl.OPENSSL_VERSION,os=platform.platform(),architecture=platform.machine(),
                cpu=cpu,logical_cpus=os.cpu_count(),clock=vars(time.get_clock_info('perf_counter')),
                constructors={n:type(hashlib.new(n,usedforsecurity=False)).__module__ for n in ALGORITHMS},
                limitations='Частота, фоновые процессы, температура и энергорежим не контролировались.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=['check','hash','collision','run'])
    ap.add_argument('--text',default='abc')
    ap.add_argument('--file',type=Path)
    ap.add_argument('--out',type=Path,default=Path('results_new'))
    ap.add_argument('--repeats',type=int,default=15)
    ap.add_argument('--target',type=float,default=0.1)
    ap.add_argument('--trials',type=int,default=1000)
    args = ap.parse_args()
    if args.mode=='hash':
        if args.file:
            hashes = {n:hashlib.new(n,usedforsecurity=False) for n in ALGORITHMS}
            with args.file.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):
                    for h in hashes.values(): h.update(block)
            print(json.dumps({n:h.hexdigest() for n,h in hashes.items()},indent=2))
        else:
            print(json.dumps({n:digest(n,args.text.encode('utf-8')).hex() for n in ALGORITHMS},indent=2))
        return
    if args.mode=='collision':
        print(json.dumps(collision(),ensure_ascii=False,indent=2)); return
    tests = check()
    if args.mode=='check':
        print(f'Пройдено {len(tests)} проверок; из них 8 внешних векторов.'); return
    if args.repeats<4 or args.trials<2 or args.target<=0:
        ap.error('Нужны repeats >= 4, trials >= 2, target > 0')
    if args.out.exists() and any(args.out.iterdir()):
        ap.error('Папка результатов не пуста; укажите новую, чтобы сохранить предыдущий опыт')
    args.out.mkdir(parents=True,exist_ok=True)
    save_json(args.out/'environment.json',environment())
    save_json(args.out/'config.json',dict(seed=SEED,repeats=args.repeats,target_seconds=args.target,
              trials=args.trials,sizes=SIZES,algorithms=ALGORITHMS))
    save_json(args.out/'checks.json',tests)
    save_json(args.out/'collision.json',collision())
    perf,fingerprints = performance(args.repeats,args.target)
    save_csv(args.out/'performance_raw.csv',perf)
    save_json(args.out/'data_sha256.json',fingerprints)
    av = avalanche(args.trials,args.out)
    save_csv(args.out/'avalanche_raw.csv',av)
    p,a = summarize(perf,av)
    save_csv(args.out/'performance_summary.csv',p)
    save_csv(args.out/'avalanche_summary.csv',a)
    save_json(args.out/'source_sha256.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest()
              for p in Path(__file__).parent.glob('*.py')})
    print('Результаты сохранены:',args.out)

if __name__=='__main__':
    main()
