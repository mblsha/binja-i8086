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


def _lift_call_expr(data: bytes, addr: int, view: FakeView | None):
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    if view is not None:
        il.source_function.view = view
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length == len(data)
    assert il.ils
    call_expr = next((expr for expr in il.ils if expr.op == "CALL"), None)
    assert call_expr is not None
    return call_expr.ops[0]


def test_call_near_rm_cs_table_resolves_to_const_pointer_with_fallback_base() -> None:
    # 2E FF 16 08 60 => call word [cs:0x6008]
    data = bytes.fromhex("2eff160860")
    addr = 0x1A338
    view = FakeView({0x16008: 0xE5, 0x16009: 0x91})

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x191E5]


def test_call_near_rm_default_cs_table_resolves_without_segment_prefix() -> None:
    # FF 16 08 60 => call word [0x6008], default segment is CS for this opcode.
    data = bytes.fromhex("ff160860")
    addr = 0x1A338
    view = FakeView({0x16008: 0xE5, 0x16009: 0x91})

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x191E5]


def test_call_near_rm_cs_table_uses_view_segment_base() -> None:
    data = bytes.fromhex("2eff160860")
    addr = 0x1A338
    view = FakeView(
        {0x1E008: 0x34, 0x1E009: 0x12},
        segments=[FakeSegment(0x18000, 0x20000)],
    )

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x19234]


def test_call_near_rm_without_view_remains_indirect() -> None:
    data = bytes.fromhex("2eff160860")
    addr = 0x1A338

    target_expr = _lift_call_expr(data, addr, view=None)

    assert target_expr.op != "CONST_PTR.l"
