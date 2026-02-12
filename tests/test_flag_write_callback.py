from __future__ import annotations

from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation
from binja_test_mocks.mock_llil import MockLowLevelILFunction

from binja_i8086.architecture import Intel8086


def _contains_ilregister(value) -> bool:
    if type(value).__name__ == "ILRegister":
        return True
    if isinstance(value, (list, tuple)):
        return any(_contains_ilregister(item) for item in value)
    ops = getattr(value, "ops", None)
    if isinstance(ops, list):
        return any(_contains_ilregister(item) for item in ops)
    return False


def test_parity_flag_write_normalizes_ilregister_operands() -> None:
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    lhs = lowlevelil.ILRegister(1)
    rhs = lowlevelil.ILRegister(2)

    expr = arch.get_flag_write_low_level_il(
        LowLevelILOperation.LLIL_ADD,
        2,
        "*",
        "p",
        [lhs, rhs],
        il,
    )

    assert expr is not None
    assert not _contains_ilregister(expr)


def test_aux_flag_write_normalizes_ilregister_operands() -> None:
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)
    lhs = lowlevelil.ILRegister(3)
    rhs = lowlevelil.ILRegister(4)

    expr = arch.get_flag_write_low_level_il(
        LowLevelILOperation.LLIL_SUB,
        2,
        "*",
        "a",
        [lhs, rhs],
        il,
    )

    assert expr is not None
    assert not _contains_ilregister(expr)


def test_flag_write_fallback_never_raises_when_base_is_unavailable() -> None:
    arch = Intel8086()
    il = MockLowLevelILFunction(arch)

    expr = arch.get_flag_write_low_level_il(
        LowLevelILOperation.LLIL_ADD,
        2,
        "*",
        "z",
        [0, 0],
        il,
    )
    assert expr is not None
    assert getattr(expr, "op", "") == "UNDEF"
