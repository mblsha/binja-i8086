from __future__ import annotations

from binja_test_mocks.mock_llil import MockLowLevelILFunction

import binja_i8086.mc as mc
from binja_i8086.architecture import Intel8086


BASE = 0x4F20
FILLER = bytes.fromhex("807f3412fedcba9876543210")


def _assert_complete_pipeline(arch: Intel8086, blob: bytes) -> None:
    decoded = mc.decode(blob, BASE)
    assert decoded is not None
    length = decoded.total_length()
    assert 0 < length <= len(blob)
    assert mc.encode(decoded, BASE) == blob[:length]
    rendered = decoded.render(BASE)
    assert isinstance(rendered, list)
    assert all(not isinstance(token, tuple) for token in rendered)

    info = arch.get_instruction_info(blob, BASE)
    assert info is not None
    assert info.length == length

    il = MockLowLevelILFunction(arch)
    assert arch.get_instruction_low_level_il(blob, BASE, il) == length
    assert il.ils


def test_every_opcode_and_second_byte_completes_the_lifting_pipeline() -> None:
    arch = Intel8086()
    for opcode in range(256):
        for second_byte in range(256):
            _assert_complete_pipeline(arch, bytes((opcode, second_byte)) + FILLER)


def test_every_two_prefix_pair_completes_the_lifting_pipeline() -> None:
    arch = Intel8086()
    prefixes = (0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3)
    for first in prefixes:
        for second in prefixes:
            for opcode in range(256):
                _assert_complete_pipeline(
                    arch,
                    bytes((first, second, opcode, 0xC0)) + FILLER,
                )
