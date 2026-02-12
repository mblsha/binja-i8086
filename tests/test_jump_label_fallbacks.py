from __future__ import annotations

from binja_test_mocks.mock_llil import MockLowLevelILFunction

from binja_i8086.architecture import Intel8086


BASE = 0x4000


def _lift_with_no_labels(data: bytes) -> MockLowLevelILFunction:
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    il.get_label_for_address = lambda _arch, _addr: None  # type: ignore[method-assign]
    length = arch.get_instruction_low_level_il(data, BASE, il)
    assert length == len(data)
    return il


def test_jcc_lift_handles_missing_fallthrough_label() -> None:
    # 74 02 => je short +2
    il = _lift_with_no_labels(bytes.fromhex("7402"))
    assert any(expr.op == "IF" for expr in il.ils)
    assert any(expr.op == "JUMP" for expr in il.ils)


def test_loop_lift_handles_missing_fallthrough_label() -> None:
    # E2 FE => loop -2
    il = _lift_with_no_labels(bytes.fromhex("e2fe"))
    assert any(expr.op == "IF" for expr in il.ils)
    assert any(expr.op == "JUMP" for expr in il.ils)
