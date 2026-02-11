from __future__ import annotations

import pytest

from binja_i8086.mc import coding, helpers


@pytest.mark.parametrize("width,value,expected", [(1, 0x12, "0x12"), (2, 0x1234, "0x1234")])
def test_fmt_hexw(width: int, value: int, expected: str) -> None:
    assert helpers.fmt_hexW(value, width) == expected


@pytest.mark.parametrize("value,expected", [(12, "12"), (0x1234, "0x1234")])
def test_fmt_imm(value: int, expected: str) -> None:
    assert helpers.fmt_imm(value) == expected


@pytest.mark.parametrize(
    "kind",
    [
        "opcode",
        "opsep",
        "instr",
        "text",
        "reg",
        "int",
        "addr",
        "codeRelAddr",
        "beginMem",
        "endMem",
    ],
)
def test_token_kinds(kind: str) -> None:
    tok = helpers.token(kind, "x", 0)
    assert tok.text == "x"


def test_decoder_encoder_roundtrip_word_and_signed() -> None:
    enc = coding.Encoder()
    enc.unsigned_byte(0x12)
    enc.signed_byte(-1)
    enc.unsigned_word(0xBEEF)
    enc.signed_word(-2)

    dec = coding.Decoder(bytes(enc.buf))
    assert dec.unsigned_byte() == 0x12
    assert dec.signed_byte() == -1
    assert dec.unsigned_word() == 0xBEEF
    assert dec.signed_word() == -2


def test_decoder_peek_and_short_buffer() -> None:
    dec = coding.Decoder(b"\xAA")
    assert dec.peek(0) == 0xAA
    with pytest.raises(coding.BufferTooShort):
        dec.peek(1)

    dec2 = coding.Decoder(b"")
    with pytest.raises(coding.BufferTooShort):
        dec2.unsigned_byte()


def test_invalid_immediate_width_raises() -> None:
    dec = coding.Decoder(b"\x00\x00")
    with pytest.raises(ValueError):
        dec.immediate(3)

    enc = coding.Encoder()
    with pytest.raises(ValueError):
        enc.immediate(1, 3)
