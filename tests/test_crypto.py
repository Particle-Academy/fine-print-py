"""Our own RC4 and AES against published known answers (as EncryptionTest)."""

from __future__ import annotations

import pytest

from fine_print.crypto import Aes, rc4


@pytest.mark.parametrize(
    ("key", "plain", "cipher"),
    [(b"Key", b"Plaintext", "BBF316E8D940AF0AD3"), (b"Wiki", b"pedia", "1021BF0420"), (b"Secret", b"Attack at dawn", "45A01F645FC35B383552544B9BF5")],
)
def test_rc4_known_answers(key: bytes, plain: bytes, cipher: str) -> None:
    assert rc4(key, plain).hex().upper() == cipher
    assert rc4(key, bytes.fromhex(cipher)) == plain


@pytest.mark.parametrize(
    ("key", "cipher"),
    [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
    ],
)
def test_fips_197_known_answers_both_ways(key: str, cipher: str) -> None:
    aes = Aes(bytes.fromhex(key))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes.encrypt_block(plain).hex() == cipher
    assert aes.decrypt_block(bytes.fromhex(cipher)) == plain


def test_sp_800_38a_cbc_known_answers() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    cipher = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    assert Aes.cbc_encrypt(key, iv, plain).hex() == cipher
    assert Aes.cbc_decrypt(key, iv, bytes.fromhex(cipher)) == plain
