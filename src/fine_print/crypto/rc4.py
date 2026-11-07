"""RC4, for PDF's standard security handler (R2-R4). Broken as a cipher; here
only to open files that already use it."""

from __future__ import annotations


def rc4(key: bytes, data: bytes) -> bytes:
    kl = len(key)
    if kl == 0:
        return data
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % kl]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for k, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)
