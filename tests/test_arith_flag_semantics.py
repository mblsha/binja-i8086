from __future__ import annotations

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockLabel

from binja_i8086.architecture import Intel8086


def _lift_to_llil(data: bytes, addr: int = 0x1000):
    arch = Intel8086()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = addr  # type: ignore[attr-defined]
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length is not None and length > 0
    return [node for node in il if not isinstance(node, MockLabel)]


def _assert_no_unimplemented_flag_exprs(llil_nodes) -> None:
    text = "\n".join(str(node).lower() for node in llil_nodes)
    assert "flag:p = unimplemented" not in text
    assert "flag:a = unimplemented" not in text


def test_cmp_al_imm8_sets_pf_af_without_unimplemented() -> None:
    # 3C 0A => cmp al, 0x0a
    llil = _lift_to_llil(bytes.fromhex("3c0a"))
    _assert_no_unimplemented_flag_exprs(llil)


def test_sub_rm8_imm8_sets_pf_af_without_unimplemented() -> None:
    # 80 6C 06 10 => sub byte [si+0x6], 0x10
    llil = _lift_to_llil(bytes.fromhex("806c0610"))
    _assert_no_unimplemented_flag_exprs(llil)
