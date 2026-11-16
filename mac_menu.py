"""Меню для защиты на macOS. Не меняет сохранённые результаты курсовой."""
import argparse
from datetime import datetime
from pathlib import Path
import html
import json
import shlex
import subprocess
import sys
import webbrowser
import hash_study as study

ROOT = Path(__file__).resolve().parent


def fresh_dir(prefix):
    path = ROOT / 'local_runs' / (prefix + '_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    path.mkdir(parents=True, exist_ok=False)
    return path


def demo(show=True):
    tests = study.check()
    data = b'abc'
    changed = bytearray(data)
    changed[0] ^= 1
    if study.distance(data, changed) != 1:
        raise RuntimeError('Входная пара отличается не одним битом')
    rows = []
    for name in study.ALGORITHMS:
        a, b = study.digest(name, data), study.digest(name, changed)
        d = study.distance(a, b)
        rows.append(dict(algorithm=name, hash_a=a.hex(), hash_b=b.hex(), changed_bits=d,
                         total_bits=8*len(a), percent=100*d/(8*len(a))))
    result = dict(environment=study.environment(), passed_checks=len(tests),
                  input_a_hex=data.hex(), input_b_hex=changed.hex(), input_distance=1,
                  avalanche_example=rows, collision=study.collision(),
                  note='Это короткая демонстрация, а не полный статистический эксперимент курсовой.')
    out = fresh_dir('demo')
    study.save_json(out/'demo.json', result)
    body = '<h1>Демонстрация хеш-функций</h1><p>Результаты этого запуска. Проверок пройдено: <b>234</b>.</p>'
    body += '<p>Входы: 616263 и 606263 (hex). Различается ровно один бит.</p>'
    body += '<table><tr><th>Функция</th><th>Изменено битов</th><th>Доля</th></tr>'
    for r in rows:
        body += f'<tr><td>{r["algorithm"]}</td><td>{r["changed_bits"]} из {r["total_bits"]}</td><td>{r["percent"]:.2f}%</td></tr>'
    body += '</table><p>Один опыт не обязан давать ровно 50%. Он не доказывает стойкость.</p>'
    body += '<h2>Опубликованная коллизия MD5</h2><p>Два различных сообщения по 128 байт, расстояние 6 бит.</p>'
    body += '<p>Общий MD5: <code>79054025255fb1a26e4bc422aef54eb4</code></p><p>Проверка воспроизводит известную пару Peter Selinger, не выполняет новый поиск.</p>'
    body += '<p><a href="https://www.mscs.dal.ca/~selinger/md5collision/">Источник пары</a></p>'
    body += '<details><summary>Все хеши и фактическая среда запуска</summary><pre>'+html.escape(json.dumps(result,ensure_ascii=False,indent=2))+'</pre></details>'
    page = '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Демонстрация хеш-функций</title><style>body{font:22px Arial;max-width:1050px;margin:45px auto;padding:20px;color:#122338}h1{font-size:36px}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #ccd4dd}pre{font-size:15px;white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}summary{cursor:pointer}</style>'+body+'</html>'
    (out/'demo.html').write_text(page,encoding='utf-8')
    print('Пройдено проверок:',len(tests))
    for r in rows: print(f'{r["algorithm"]:10} {r["changed_bits"]:3}/{r["total_bits"]}  {r["percent"]:.2f}%')
    print('Коллизия MD5 подтверждена. Отчёт:',out/'demo.html')
    if show: webbrowser.open((out/'demo.html').as_uri())
    return out


def run_script(*args):
    subprocess.run([sys.executable,str(ROOT/args[0]),*args[1:]],cwd=ROOT,check=True)


def menu():
    print('Хеш-функции. Курсовая Лобанова Д. И.\nPython:',sys.version.split()[0])
    while True:
        print('\n1  Демонстрация для защиты (откроется отчёт)\n2  Проверить 234 теста\n3  Хешировать текст\n4  Хешировать файл\n5  Полный эксперимент в новой папке\n6  Открыть графики из курсовой\n0  Выход')
        try:
            choice = input('Номер действия: ').strip()
            if choice=='0': return
            if choice=='1': demo()
            elif choice=='2': run_script('hash_study.py','check')
            elif choice=='3': run_script('hash_study.py','hash','--text',input('Текст: '))
            elif choice=='4':
                raw=input('Перетащите файл из Finder сюда и нажмите Enter: ').strip()
                if Path(raw).expanduser().is_file(): path=Path(raw).expanduser()
                else:
                    parts=shlex.split(raw)
                    if len(parts)!=1: raise ValueError('Выберите один файл')
                    path=Path(parts[0]).expanduser()
                if not path.is_file(): raise ValueError('Файл не найден')
                run_script('hash_study.py','hash','--file',str(path))
            elif choice=='5':
                out=fresh_dir('experiment')
                print('Полный опыт занимает несколько минут. Сохранённая папка results не изменяется.')
                run_script('hash_study.py','run','--out',str(out))
                run_script('plot_results.py',str(out))
                webbrowser.open((out/'speed.svg').as_uri())
                webbrowser.open((out/'avalanche.svg').as_uri())
            elif choice=='6':
                for name in ('speed.svg','avalanche.svg'):webbrowser.open((ROOT/'results'/name).as_uri())
            else: print('Введите число из меню.')
        except (ValueError,OSError,subprocess.CalledProcessError) as exc: print('Действие не выполнено:',exc)
        except (KeyboardInterrupt,EOFError): print('\nРабота остановлена.');return


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo',action='store_true')
    parser.add_argument('--no-open',action='store_true')
    args=parser.parse_args()
    if args.demo:demo(not args.no_open)
    else:menu()
