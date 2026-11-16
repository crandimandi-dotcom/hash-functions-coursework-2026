"""Учебная реализация полного SHA-256 по FIPS 180-4, раздел 6.2.
Не предназначена для промышленного применения. Стандартные константы
взяты из FIPS 180-4; код преобразования написан для данного проекта.
"""
import struct

MASK = 0xffffffff
K = tuple(int(x, 16) for x in '''
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
'''.split())


def rotr(x, n):
    """Циклический сдвиг 32-битного слова вправо."""
    return ((x >> n) | (x << (32 - n))) & MASK


def sha256(data: bytes) -> bytes:
    """Возвращает 32 байта хеша для байтового сообщения."""
    bit_length = len(data) * 8
    if bit_length >= 2**64:
        raise ValueError('Сообщение слишком длинное для SHA-256')
    # Бит 1, нули до 56 байт по модулю 64, затем 64-битная длина.
    padded = data + b'\x80'
    padded += b'\x00' * ((56 - len(padded)) % 64)
    padded += struct.pack('>Q', bit_length)
    state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for offset in range(0, len(padded), 64):
        w = list(struct.unpack('>16I', padded[offset:offset + 64]))
        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & MASK)
        a, b, c, d, e, f, g, h = state
        for i in range(64):
            big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            choice = (e & f) ^ ((~e) & g)
            t1 = (h + big1 + choice + K[i] + w[i]) & MASK
            big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big0 + majority) & MASK
            a, b, c, d, e, f, g, h = ((t1+t2) & MASK, a, b, c,
                                      (d+t1) & MASK, e, f, g)
        state = [(x+y) & MASK for x, y in zip(state, (a,b,c,d,e,f,g,h))]
    return struct.pack('>8I', *state)
