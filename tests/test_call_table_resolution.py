from __future__ import annotations

from dataclasses import dataclass

from binja_test_mocks.mock_llil import MockLowLevelILFunction

from binja_i8086.architecture import Intel8086, Intel8086Vanilla


@dataclass
class FakeSegment:
    start: int
    end: int


@dataclass
class FakeSymbol:
    name: str
    raw_name: str | None = None


class FakeView:
    def __init__(
        self,
        memory: dict[int, int],
        segments: list[FakeSegment] | None = None,
        symbols: dict[int, FakeSymbol] | None = None,
    ):
        self._memory = memory
        self.segments = segments or []
        self._symbols = symbols or {}

    def read(self, addr: int, length: int) -> bytes:
        return bytes(self._memory.get(addr + i, 0) for i in range(length))

    def get_segment_at(self, addr: int):
        for segment in self.segments:
            if segment.start <= addr < segment.end:
                return segment
        return None

    def get_symbol_at(self, addr: int):
        return self._symbols.get(addr)


def _lift_call_expr(data: bytes, addr: int, view: FakeView | None, arch: Intel8086 | None = None):
    if arch is None:
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


def test_call_near_rm_cs_table_zero_entry_stays_indirect() -> None:
    data = bytes.fromhex("ff160860")
    addr = 0x1A338
    view = FakeView({0x16008: 0x00, 0x16009: 0x00})

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op != "CONST_PTR.l"


def test_call_near_rm_cs_table_lift_can_be_disabled() -> None:
    data = bytes.fromhex("2eff160860")
    addr = 0x1A338
    view = FakeView({0x16008: 0xE5, 0x16009: 0x91})
    arch = Intel8086()
    arch.cs_table_lift = False

    target_expr = _lift_call_expr(data, addr, view, arch)

    assert target_expr.op != "CONST_PTR.l"


def test_call_near_rm_cs_table_lift_disabled_by_vanilla_arch() -> None:
    data = bytes.fromhex("2eff160860")
    addr = 0x1A338
    view = FakeView({0x16008: 0xE5, 0x16009: 0x91})

    target_expr = _lift_call_expr(data, addr, view, Intel8086Vanilla())

    assert target_expr.op != "CONST_PTR.l"

def test_call_near_rm_cs_table_prefers_page_base_over_overlay_segment() -> None:
    # 2E FF 16 04 30 => call word [cs:0x3004]
    # Runtime images can have a broad mapped segment plus narrower overlay segments.
    # Use the 64K page base (0x10000 here), not the overlay start (0x16000).
    data = bytes.fromhex("2eff160430")
    addr = 0x1A338
    view = FakeView(
        {0x13004: 0x29, 0x13005: 0x3F},
        segments=[FakeSegment(0x16000, 0x1B000), FakeSegment(0x0, 0x50000)],
    )

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x13F29]

def test_call_near_rm_cs_table_resolves_from_il_view_when_source_view_missing() -> None:
    # Some BN analysis paths populate il.view but do not expose source_function.view.
    data = bytes.fromhex("2eff160430")
    addr = 0x1A338
    view = FakeView({0x13004: 0x29, 0x13005: 0x3F}, segments=[FakeSegment(0x10000, 0x20000)])

    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    il.view = view

    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length == len(data)

    call_expr = next((expr for expr in il.ils if expr.op == "CALL"), None)
    assert call_expr is not None
    target_expr = call_expr.ops[0]
    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x13F29]



def test_call_near_rm_cs_table_zero_entry_uses_synthetic_callvec_target() -> None:
    data = bytes.fromhex("2eff161220")
    addr = 0x16179
    view = FakeView(
        {0x12012: 0x00, 0x12013: 0x00},
        symbols={0x2012: FakeSymbol("town_runtime_callvec_2012_draw_main_border")},
    )

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0xF2012]


def test_call_near_rm_cs_table_zero_entry_uses_mapped_slot_symbol_for_callvec() -> None:
    data = bytes.fromhex("2eff161220")
    addr = 0x16179
    view = FakeView(
        {0x12012: 0x00, 0x12013: 0x00},
        symbols={0x12012: FakeSymbol("town_runtime_callvec_2012_draw_main_border")},
    )

    target_expr = _lift_call_expr(data, addr, view)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0xF2012]


def test_call_near_imm_uses_const_pointer_target() -> None:
    # E8 6F 00 at 0x1A476 -> target 0x1A4E8.
    data = bytes.fromhex("e86f00")
    addr = 0x1A476

    target_expr = _lift_call_expr(data, addr, view=None)

    assert target_expr.op == "CONST_PTR.l"
    assert target_expr.ops == [0x1A4E8]
