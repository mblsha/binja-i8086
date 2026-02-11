from __future__ import annotations

from typing import Iterable

from binja_test_mocks.mock_llil import MockLowLevelILFunction

import binja_i8086.mc as mc
from binja_i8086.architecture import Intel8086


BASE = 0x4000
EXPECTED_UNSUPPORTED_OPCODES = {0x27, 0x2F, 0x37, 0x3F, 0xD4, 0xD5}


def _candidate_streams(opcode: int) -> Iterable[bytes]:
    # Fast path candidates that cover many fixed/immediate/modrm forms.
    seeds = [
        bytes([opcode]),
        bytes([opcode, 0x00]),
        bytes([opcode, 0x00, 0x00]),
        bytes([opcode, 0x00, 0x00, 0x00]),
        bytes([opcode, 0x00, 0x00, 0x00, 0x00]),
        bytes([opcode, 0xC0, 0x00, 0x00, 0x00, 0x00]),
        bytes([opcode, 0x06, 0x34, 0x12, 0x00, 0x00]),
        bytes([opcode, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ]
    for seed in seeds:
        yield seed

    # Exhaustive modrm fallback.
    for modrm in range(256):
        yield bytes([opcode, modrm, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def _find_decodable_stream(opcode: int) -> bytes:
    for blob in _candidate_streams(opcode):
        decoded = mc.decode(blob, BASE)
        if decoded is None:
            continue
        if decoded.total_length() <= len(blob):
            return blob
    raise AssertionError(f"could not decode opcode 0x{opcode:02x}")


def test_decode_encode_render_analyze_lift_across_opcode_space() -> None:
    arch = Intel8086()

    decoded_count = 0
    il_count = 0

    for opcode in range(256):
        if opcode in EXPECTED_UNSUPPORTED_OPCODES:
            # Current plugin behavior: these legacy adjust opcodes are not
            # modeled yet, so they intentionally decode as unknown.
            continue
        blob = _find_decodable_stream(opcode)
        decoded = mc.decode(blob, BASE)
        assert decoded is not None
        decoded_count += 1

        length = decoded.total_length()
        assert length > 0

        # Roundtrip must preserve consumed bytes.
        encoded = mc.encode(decoded, BASE)
        assert encoded == blob[:length]

        # Render/analyze smoke.
        rendered = decoded.render(BASE)
        assert isinstance(rendered, list)
        info = arch.get_instruction_info(blob, BASE)
        assert info is not None
        assert info.length == length

        # Text + LLIL smoke.
        text_res = arch.get_instruction_text(blob, BASE)
        assert text_res is not None
        _tokens, text_len = text_res
        assert text_len == length

        il = MockLowLevelILFunction(arch)
        ll_len = arch.get_instruction_low_level_il(blob, BASE, il)
        assert ll_len == length
        assert len(il.ils) >= 1
        il_count += len(il.ils)

    # Guardrails to ensure this remains a broad behavior gate.
    assert decoded_count == 256 - len(EXPECTED_UNSUPPORTED_OPCODES)
    assert il_count > 256
