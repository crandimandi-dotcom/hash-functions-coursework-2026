"""Дополнительные проверки финального аудита; Python 3.10+, без пакетов."""
import hashlib,json,math,random,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
import hash_study as h
from sha256_reference import sha256

class AuditTests(unittest.TestCase):
    def test_standard_checks(self): self.assertEqual(len(h.check()),234)
    def test_sha256_million_a(self):
        self.assertEqual(sha256(b'a'*1000000).hex(),'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
    def test_padding_and_random_messages(self):
        rng=random.Random(81261)
        for n in list(range(0,140))+[511,512,513,4095,4096,8193]:
            with self.subTest(n=n):
                data=rng.randbytes(n);self.assertEqual(sha256(data),hashlib.sha256(data).digest())
    def test_distance_rejects_mismatch(self):
        with self.assertRaises(ValueError): h.distance(b'a',b'')
    def test_collision(self):
        c=h.collision();self.assertEqual((c['length_a'],c['length_b'],c['input_distance']),(128,128,6))
        self.assertEqual([x['equal'] for x in c['results']],[True,False,False,False,False,False])
    def test_cli_utf8_and_large_file(self):
        root=Path(__file__).resolve().parent
        for text in ['','Привет, Данил!','abc\n']:
            out=subprocess.check_output([sys.executable,str(root/'hash_study.py'),'hash','--text',text],text=True)
            self.assertEqual(json.loads(out),{n:h.digest(n,text.encode()).hex() for n in h.ALGORITHMS})
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/'файл с пробелами.bin';data=bytes(range(256))*8193;f.write_bytes(data)
            out=subprocess.check_output([sys.executable,str(root/'hash_study.py'),'hash','--file',str(f)],text=True)
            self.assertEqual(json.loads(out),{n:h.digest(n,data).hex() for n in h.ALGORITHMS})
    def test_invalid_parameters(self):
        root=Path(__file__).resolve().parent
        for v in ['nan','inf','-inf','0','-1']:
            proc=subprocess.run([sys.executable,str(root/'hash_study.py'),'run','--target='+v],capture_output=True,timeout=10)
            self.assertEqual(proc.returncode,2,v)
    def test_saved_data_under_optimization(self):
        root=Path(__file__).resolve().parent
        p=subprocess.run([sys.executable,'-O',str(root/'verify_saved.py')],capture_output=True,timeout=20)
        self.assertEqual(p.returncode,0,p.stderr.decode())

    def test_corrupted_data_rejected_under_optimization(self):
        root=Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as td:
            copied=Path(td)/'project';shutil.copytree(root,copied,ignore=shutil.ignore_patterns('__pycache__','local_runs'))
            f=copied/'results/performance_summary.csv'
            rows=f.read_text().splitlines();cols=rows[1].split(',');cols[-1]='999999';rows[1]=','.join(cols)
            f.write_text('\n'.join(rows)+'\n')
            p=subprocess.run([sys.executable,'-O',str(copied/'verify_saved.py')],capture_output=True,timeout=20)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('MiB/s',p.stderr.decode())

if __name__=='__main__':unittest.main(verbosity=2)
