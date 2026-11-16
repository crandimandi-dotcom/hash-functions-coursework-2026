"""Создание SVG-графиков из CSV; только стандартная библиотека Python."""
import argparse
import csv
import math
from html import escape
from pathlib import Path

NAMES = {'md5':'MD5','sha1':'SHA-1','sha256':'SHA-256','sha512':'SHA-512',
         'sha3_256':'SHA3-256','sha3_512':'SHA3-512'}
COLORS = ['#111111','#777777','#1460a0','#a52c2c','#23733d','#8a4a95']


def text(x,y,s,size=19,anchor='middle'):
    return f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}">{escape(str(s))}</text>'


def draw(folder, kind):
    rows = list(csv.DictReader((folder/f'{kind}_summary.csv').open(encoding='utf-8')))
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="620" viewBox="0 0 1000 620">',
           '<rect width="1000" height="620" fill="white"/>',
           '<g font-family="Arial, sans-serif" fill="#111">']
    x0,y0,w,h = 95,45,850,440
    if kind=='performance':
        x = lambda v:x0+math.log2(v)/23*w
        ymax = math.ceil(max(float(r['mib_per_s']) for r in rows)/500)*500
        y = lambda v:y0+h-v/ymax*h
        yticks = range(0,ymax+1,500)
        xticks = [(1,'1 Б'),(64,'64 Б'),(1024,'1 KiB'),(65536,'64 KiB'),(1048576,'1 MiB'),(8388608,'8 MiB')]
        label = 'Скорость, MiB/s'
    else:
        x = lambda v:{16:200,64:520,1024:840}[v]
        means=[float(row['mean_percent']) for row in rows]
        low=min(49,math.floor(min(means)*2)/2)
        high=max(51,math.ceil(max(means)*2)/2)
        y = lambda v:y0+h-(v-low)/(high-low)*h
        step=max(0.5,math.ceil((high-low)/4*2)/2)
        yticks = [low+i*step for i in range(int((high-low)/step)+1)]
        xticks = [(16,'16 байт'),(64,'64 байта'),(1024,'1024 байта')]
        label = 'Средняя доля, %'
    for tick in yticks:
        yy=y(tick)
        out += [f'<path d="M{x0},{yy}H{x0+w}" stroke="#ddd"/>',text(x0-12,yy+6,tick,18,'end')]
    for value,label_x in xticks:
        xx=x(value)
        out.append(text(xx,y0+h+30,label_x,18))
    out += [f'<path d="M{x0},{y0}V{y0+h}H{x0+w}" fill="none" stroke="#111"/>',text(x0,y0-16,label,20,'start')]
    for i,(name,label_name) in enumerate(NAMES.items()):
        rr=[r for r in rows if r['algorithm']==name and int(r['size_bytes'])>0]
        points=[(x(int(r['size_bytes'])),y(float(r['mib_per_s'] if kind=='performance' else r['mean_percent']))) for r in rr]
        out.append('<polyline points="'+' '.join(f'{xx:.2f},{yy:.2f}' for xx,yy in points)+f'" fill="none" stroke="{COLORS[i]}" stroke-width="2.5"/>')
        for xx,yy in points:
            out.append(f'<circle cx="{xx}" cy="{yy}" r="4.3" fill="{COLORS[i]}"/>')
        lx=110+(i%3)*300;ly=555+(i//3)*33
        out += [f'<path d="M{lx},{ly-5}h35" stroke="{COLORS[i]}" stroke-width="3"/>',text(lx+45,ly,label_name,20,'start')]
    out.append('</g></svg>')
    target=folder/('speed.svg' if kind=='performance' else 'avalanche.svg')
    target.write_text('\n'.join(out),encoding='utf-8')
    print(target)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('folder',type=Path)
    args=ap.parse_args()
    for kind in ('performance','avalanche'): draw(args.folder,kind)
