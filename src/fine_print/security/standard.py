"""PDF's standard security handler, EMPTY user password only, as PHP's
``FinePrint\\Security\\StandardSecurity`` (owner ruling 2026-10-21).

V1/R2 and V2/R3 (RC4), V4/R4 (RC4 or AES-128 crypt filters), V5/R5 and V5/R6
(AES-256). Never tries a password other than "". Never reports the key, /O,
/U or anything derived from them.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from ..crypto.aes import Aes
from ..crypto.rc4 import rc4
from ..exceptions import RefusedException
from ..limits import Budget
from ..objects import PdfDict, PdfName, PdfString

PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")
SLICE = 65536
PERMISSIONS = {
    "print": 3,
    "modify": 4,
    "copy": 5,
    "annotate": 6,
    "fillForms": 9,
    "accessibility": 10,
    "assemble": 11,
    "printHighQuality": 12,
}


def _md5(b: bytes) -> bytes:
    return hashlib.md5(b, usedforsecurity=False).digest()


def _corrupt(what: str) -> RefusedException:
    return RefusedException("corrupt", f"The file's encryption dictionary {what}.")


def _needs_password() -> RefusedException:
    return RefusedException(
        "encrypted",
        "The file needs a password to open. Only files that open with an empty password are read.",
    )


def _int(v: Any, key: str) -> int:
    if type(v) is not int:
        raise _corrupt(f"has a /{key} that is not an integer")
    return v


def _bytes(v: Any, key: str, minimum: int) -> bytes:
    if not isinstance(v, PdfString) or len(v.bytes) < minimum:
        raise _corrupt(f"has a missing or short /{key}")
    return v.bytes


def _method(name: Any, cf: Any, v: int, resolve: Callable[[Any], Any]) -> str:
    if name is None:
        return "identity"
    if not isinstance(name, PdfName):
        raise _corrupt("names its crypt filter with something that is not a name")
    if name.value == "Identity":
        return "identity"
    flt = resolve(cf.get(name.value)) if isinstance(cf, PdfDict) else None
    if not isinstance(flt, PdfDict):
        raise _corrupt("names a crypt filter it does not define")
    cfm = resolve(flt.get("CFM"))
    cfm_name = cfm.value if isinstance(cfm, PdfName) else "None"
    if cfm_name == "None":
        return "identity"
    if cfm_name == "V2" and v == 4:
        return "rc4"
    if cfm_name == "AESV2" and v == 4:
        return "aes128"
    if cfm_name == "AESV3" and v == 5:
        return "aes256"
    raise RefusedException("encrypted", "The file uses a crypt method that is not supported.")


def _key_r4(o: bytes, p: int, id0: bytes, r: int, n: int, encrypt_metadata: bool) -> bytes:
    data = PAD + o[:32] + (p & 0xFFFFFFFF).to_bytes(4, "little") + id0
    if r >= 4 and not encrypt_metadata:
        data += b"\xff\xff\xff\xff"
    h = _md5(data)
    if r >= 3:
        for _ in range(50):
            h = _md5(h[:n])
    return h[: 5 if r == 2 else n]


def _user_matches(key: bytes, u: bytes, id0: bytes, r: int) -> bool:
    if r == 2:
        return hmac.compare_digest(u[:32], rc4(key, PAD))
    x = rc4(key, _md5(PAD + id0))
    for i in range(1, 20):
        x = rc4(bytes(b ^ i for b in key), x)
    return hmac.compare_digest(u[:16], x)


def _hash_r6(password: bytes, salt: bytes, udata: bytes, r: int, budget: Budget) -> bytes:
    k = hashlib.sha256(password + salt + udata).digest()
    if r == 5:
        return k
    for i in range(300):
        e = Aes.cbc_encrypt(k[:16], k[16:32], (password + k + udata) * 64)
        total = sum(e[:16])
        k = hashlib.new(("sha256", "sha384", "sha512")[total % 3], e).digest()
        budget.tick(64)
        if i >= 63 and e[-1] <= i - 31:
            break
    return k[:32]


class StandardSecurity:
    def __init__(self, v: int, r: int, p: int, encrypt_metadata: bool, budget: Budget) -> None:
        self._v = v
        self._r = r
        self._p = p
        self.encrypt_metadata = encrypt_metadata
        self._budget = budget
        self._key = b""
        self._streams = "identity"
        self._strings = "identity"

    @staticmethod
    def open(enc: PdfDict, id0: bytes, resolve: Callable[[Any], Any], budget: Budget) -> StandardSecurity:
        flt = resolve(enc.get("Filter"))
        if not isinstance(flt, PdfName):
            raise _corrupt("has no /Filter naming its security handler")
        if flt.value != "Standard":
            raise RefusedException(
                "encrypted",
                "The file is encrypted with a security handler other than the standard one (certificates, or a vendor handler), which is not supported.",
            )
        vv = resolve(enc.get("V"))
        v = _int(0 if vv is None else vv, "V")
        r = _int(resolve(enc.get("R")), "R")
        p = _int(resolve(enc.get("P")), "P") & 0xFFFFFFFF
        p = p - 0x100000000 if p >= 0x80000000 else p
        if v not in (1, 2, 4, 5) or r not in (2, 3, 4, 5, 6) or (v <= 2 and r > 3) or (v == 4 and r != 4) or (v == 5 and r < 5):
            raise RefusedException("encrypted", f"The file uses an encryption version that is not supported (V {v}, R {r}).")
        meta = resolve(enc.get("EncryptMetadata"))
        s = StandardSecurity(v, r, p, meta is not False, budget)

        bits = resolve(enc.get("Length"))
        if bits is not None and (type(bits) is not int or bits % 8 != 0 or bits < 40 or (v < 5 and bits > 128) or bits > 256):
            raise _corrupt("declares a key length that is not a multiple of 8 between 40 and 128 bits")
        n = 5 if v == 1 else (bits if bits is not None else (128 if v >= 4 else 40)) // 8
        if v <= 2:
            s._streams = s._strings = "rc4"
        else:
            cf = resolve(enc.get("CF"))
            s._streams = _method(resolve(enc.get("StmF")), cf, v, resolve)
            s._strings = _method(resolve(enc.get("StrF")), cf, v, resolve)

        if r <= 4:
            o = _bytes(resolve(enc.get("O")), "O", 32)
            u = _bytes(resolve(enc.get("U")), "U", 32)
            key = _key_r4(o, p, id0, r, n, s.encrypt_metadata)
            if not _user_matches(key, u, id0, r):
                raise _needs_password()
        else:
            _bytes(resolve(enc.get("O")), "O", 48)
            u = _bytes(resolve(enc.get("U")), "U", 48)
            ue = _bytes(resolve(enc.get("UE")), "UE", 32)
            if len(ue) != 32 or len(_bytes(resolve(enc.get("OE")), "OE", 32)) != 32:
                raise _corrupt("has /OE or /UE of the wrong length")
            vs = u[32:40]
            ks = u[40:48]
            if not hmac.compare_digest(u[:32], _hash_r6(b"", vs, b"", r, budget)):
                raise _needs_password()
            key = Aes.cbc_decrypt(_hash_r6(b"", ks, b"", r, budget), b"\x00" * 16, ue)
        s._key = key
        return s

    def string(self, data: bytes, num: int, gen: int) -> bytes | None:
        return self._decrypt(self._strings, data, num, gen)

    def stream(self, data: bytes, num: int, gen: int) -> bytes | None:
        return self._decrypt(self._streams, data, num, gen)

    def report(self) -> dict[str, Any]:
        perms = {name: (self._p & (1 << (bit - 1))) != 0 for name, bit in PERMISSIONS.items()}
        method = self._strings if self._streams == "identity" else self._streams
        algorithm = {"aes128": "AES-128", "aes256": "AES-256"}.get(method)
        if algorithm is None:
            algorithm = f"RC4-{8 * len(self._key)}" if method == "rc4" else "none"
        return {
            "encrypted": True,
            "handler": "Standard",
            "version": self._v,
            "revision": self._r,
            "algorithm": algorithm,
            "encryptMetadata": self.encrypt_metadata,
            "permissions": perms,
        }

    def _decrypt(self, method: str, data: bytes, num: int, gen: int) -> bytes | None:
        if method == "identity" or data == b"":
            return data
        if method == "rc4":
            out = rc4(self._object_key(num, gen, False), data)
            self._budget.check()
            return out
        if len(data) < 32 or len(data) % 16 != 0:
            return None
        key = self._key if method == "aes256" else self._object_key(num, gen, True)
        iv = data[:16]
        body = data[16:]
        out = bytearray()
        for i in range(0, len(body), SLICE):
            piece = body[i : i + SLICE]
            out += Aes.cbc_decrypt(key, iv, piece)
            iv = piece[-16:]
            self._budget.check()
        pad = out[-1]
        if 1 <= pad <= 16 and out[-pad:] == bytes((pad,)) * pad:
            del out[-pad:]
        return bytes(out)

    def _object_key(self, num: int, gen: int, aes: bool) -> bytes:
        k = self._key + (num & 0xFFFFFFFF).to_bytes(4, "little")[:3] + (gen & 0xFFFFFFFF).to_bytes(4, "little")[:2]
        if aes:
            k += b"sAlT"
        return _md5(k)[: min(len(self._key) + 5, 16)]
