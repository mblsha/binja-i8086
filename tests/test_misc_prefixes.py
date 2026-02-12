from __future__ import annotations

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockLabel, mllil

from binja_i8086.architecture import Intel8086


def _lift_to_llil(arch: Intel8086, data: bytes, addr: int = 0x1000):
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = addr  # type: ignore[attr-defined]
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length is not None and length > 0
    return [node for node in il if not isinstance(node, MockLabel)]


def test_lock_prefix_lifts_wrapped_instruction_instead_of_unimplemented() -> None:
    arch = Intel8086()
    # F0 90 => lock nop
    llil = _lift_to_llil(arch, b"\xF0\x90")
    assert llil == [mllil("NOP", [])]
