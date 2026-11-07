"""AES (FIPS-197), 128/192/256-bit keys, table-driven, as PHP's
``FinePrint\\Crypto\\Aes``. The S-box is generated from its definition; the
FIPS-197 and SP 800-38A known answers pin it. Not constant-time: it opens files
a user handed us with an empty password, and must not become a general cipher.
"""

from __future__ import annotations

import struct


def _xtime(b: int) -> int:
    return ((b << 1) ^ (0x1B if b & 0x80 else 0)) & 0xFF


def _mul(a: int, b: int) -> int:
    p = 0
    while b > 0:
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _tables() -> tuple[list[int], list[int], list[list[int]], list[list[int]]]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09

        def rot(x: int, n: int) -> int:
            return ((x << n) | (x >> (8 - n))) & 0xFF

        sbox[p] = (q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    te: list[list[int]] = [[0] * 256 for _ in range(4)]
    td: list[list[int]] = [[0] * 256 for _ in range(4)]
    for x in range(256):
        s = sbox[x]
        e = (_mul(s, 2) << 24) | (s << 16) | (s << 8) | _mul(s, 3)
        i = inv[x]
        d = (_mul(i, 14) << 24) | (_mul(i, 9) << 16) | (_mul(i, 13) << 8) | _mul(i, 11)
        for r in range(4):
            te[r][x] = e
            td[r][x] = d
            e = ((e >> 8) | (e << 24)) & 0xFFFFFFFF
            d = ((d >> 8) | (d << 24)) & 0xFFFFFFFF
    return sbox, inv, te, td


_SBOX, _INV, _TE, _TD = _tables()


class Aes:
    def __init__(self, key: bytes) -> None:
        n = len(key)
        if n not in (16, 24, 32):
            raise ValueError("An AES key is 16, 24 or 32 bytes.")
        nk = n // 4
        self._rounds = nk + 6
        total = 4 * (self._rounds + 1)
        w = list(struct.unpack(f">{nk}I", key))
        rcon = 1
        s = _SBOX
        for i in range(nk, total):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) & 0xFFFFFFFF) | (t >> 24)
                t = (s[t >> 24] << 24) | (s[(t >> 16) & 0xFF] << 16) | (s[(t >> 8) & 0xFF] << 8) | s[t & 0xFF]
                t ^= rcon << 24
                rcon = _xtime(rcon)
            elif nk > 6 and i % nk == 4:
                t = (s[t >> 24] << 24) | (s[(t >> 16) & 0xFF] << 16) | (s[(t >> 8) & 0xFF] << 8) | s[t & 0xFF]
            w.append(w[i - nk] ^ t)
        self._ek = w
        td0, td1, td2, td3 = _TD
        dk: list[int] = []
        for r in range(self._rounds + 1):
            for c in range(4):
                k = w[4 * (self._rounds - r) + c]
                if 0 < r < self._rounds:
                    k = td0[s[k >> 24]] ^ td1[s[(k >> 16) & 0xFF]] ^ td2[s[(k >> 8) & 0xFF]] ^ td3[s[k & 0xFF]]
                dk.append(k)
        self._dk = dk

    def encrypt_block(self, block: bytes) -> bytes:
        te0, te1, te2, te3 = _TE
        s = _SBOX
        k = self._ek
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        s0 ^= k[0]
        s1 ^= k[1]
        s2 ^= k[2]
        s3 ^= k[3]
        for r in range(1, self._rounds):
            o = 4 * r
            t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ k[o]
            t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ k[o + 1]
            t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ k[o + 2]
            t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ k[o + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        o = 4 * self._rounds
        return struct.pack(
            ">4I",
            ((s[s0 >> 24] << 24) | (s[(s1 >> 16) & 0xFF] << 16) | (s[(s2 >> 8) & 0xFF] << 8) | s[s3 & 0xFF]) ^ k[o],
            ((s[s1 >> 24] << 24) | (s[(s2 >> 16) & 0xFF] << 16) | (s[(s3 >> 8) & 0xFF] << 8) | s[s0 & 0xFF]) ^ k[o + 1],
            ((s[s2 >> 24] << 24) | (s[(s3 >> 16) & 0xFF] << 16) | (s[(s0 >> 8) & 0xFF] << 8) | s[s1 & 0xFF]) ^ k[o + 2],
            ((s[s3 >> 24] << 24) | (s[(s0 >> 16) & 0xFF] << 16) | (s[(s1 >> 8) & 0xFF] << 8) | s[s2 & 0xFF]) ^ k[o + 3],
        )

    def decrypt_block(self, block: bytes) -> bytes:
        td0, td1, td2, td3 = _TD
        si = _INV
        k = self._dk
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        s0 ^= k[0]
        s1 ^= k[1]
        s2 ^= k[2]
        s3 ^= k[3]
        for r in range(1, self._rounds):
            o = 4 * r
            t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xFF] ^ td2[(s2 >> 8) & 0xFF] ^ td3[s1 & 0xFF] ^ k[o]
            t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xFF] ^ td2[(s3 >> 8) & 0xFF] ^ td3[s2 & 0xFF] ^ k[o + 1]
            t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xFF] ^ td2[(s0 >> 8) & 0xFF] ^ td3[s3 & 0xFF] ^ k[o + 2]
            t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xFF] ^ td2[(s1 >> 8) & 0xFF] ^ td3[s0 & 0xFF] ^ k[o + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        o = 4 * self._rounds
        return struct.pack(
            ">4I",
            ((si[s0 >> 24] << 24) | (si[(s3 >> 16) & 0xFF] << 16) | (si[(s2 >> 8) & 0xFF] << 8) | si[s1 & 0xFF]) ^ k[o],
            ((si[s1 >> 24] << 24) | (si[(s0 >> 16) & 0xFF] << 16) | (si[(s3 >> 8) & 0xFF] << 8) | si[s2 & 0xFF]) ^ k[o + 1],
            ((si[s2 >> 24] << 24) | (si[(s1 >> 16) & 0xFF] << 16) | (si[(s0 >> 8) & 0xFF] << 8) | si[s3 & 0xFF]) ^ k[o + 2],
            ((si[s3 >> 24] << 24) | (si[(s2 >> 16) & 0xFF] << 16) | (si[(s1 >> 8) & 0xFF] << 8) | si[s0 & 0xFF]) ^ k[o + 3],
        )

    @staticmethod
    def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(iv) != 16 or len(data) % 16 != 0:
            raise ValueError("CBC needs a 16-byte IV and whole 16-byte blocks.")
        aes = Aes(key)
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            x = int.from_bytes(data[i : i + 16], "big") ^ int.from_bytes(prev, "big")
            prev = aes.encrypt_block(x.to_bytes(16, "big"))
            out += prev
        return bytes(out)

    @staticmethod
    def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(iv) != 16 or len(data) % 16 != 0:
            raise ValueError("CBC needs a 16-byte IV and whole 16-byte blocks.")
        aes = Aes(key)
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i : i + 16]
            x = int.from_bytes(aes.decrypt_block(block), "big") ^ int.from_bytes(prev, "big")
            out += x.to_bytes(16, "big")
            prev = block
        return bytes(out)
