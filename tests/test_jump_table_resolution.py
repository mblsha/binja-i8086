from __future__ import annotations

from dataclasses import dataclass

from binja_test_mocks.mock_llil import MockLowLevelILFunction

from binja_i8086.architecture import Intel8086


@dataclass
class FakeSegment:
    start: int
    end: int


class FakeView:
    def __init__(self, memory: dict[int, int], segments: list[FakeSegment] | None = None):
        self._memory = memory
        self.segments = segments or []

    def read(self, addr: int, length: int) -> bytes:
        return bytes(self._memory.get(addr + i, 0) for i in range(length))

    def get_segment_at(self, addr: int):
        for segment in self.segments:
            if segment.start <= addr < segment.end:
                return segment
        return None


def _lift_jump_expr(data: bytes, addr: int, view: FakeView | None):
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    if view is not None:
        il.source_function.view = view
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length == len(data)
    assert il.ils
    jump_expr = next((expr for expr in il.ils if expr.op == "JUMP"), None)
    assert jump_expr is not None
    return jump_expr.ops[0]


def test_jmp_near_rm_default_cs_table_resolves_to_const_pointer() -> None:
    # FF 26 32 60 => jmp word [0x6032], default segment is CS.
    data = bytes.fromhex("ff263260")
    addr = 0x1A51E
    view = FakeView({0x16032: 0xD5, 0x16033: 0x96})

    target_expr = _lift_jump_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x196D5]


def test_jmp_near_rm_cs_table_zero_entry_stays_indirect() -> None:
    data = bytes.fromhex("ff263260")
    addr = 0x1A51E
    view = FakeView({0x16032: 0x00, 0x16033: 0x00})

    target_expr = _lift_jump_expr(data, addr, view)

    assert target_expr.op != "CONST_PTR.l"

def test_jmp_near_rm_cs_table_prefers_page_base_over_overlay_segment() -> None:
    # FF 26 04 30 => jmp word [0x3004], default segment is CS.
    data = bytes.fromhex("ff260430")
    addr = 0x1A51E
    view = FakeView(
        {0x13004: 0x29, 0x13005: 0x3F},
        segments=[FakeSegment(0x16000, 0x1B000), FakeSegment(0x0, 0x50000)],
    )

    target_expr = _lift_jump_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x13F29]

