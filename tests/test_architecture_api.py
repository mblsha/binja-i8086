from __future__ import annotations

from binja_test_mocks.mock_llil import MockLowLevelILFunction

from binja_i8086.architecture import Intel8086


BASE = 0x1000


def _render_text(tokens) -> str:
    return "".join(tok.text for tok in tokens)


def test_basic_metadata() -> None:
    arch = Intel8086()
    assert arch.name == "8086"
    assert arch.stack_pointer == "sp"
    assert arch.address_size == 3
    assert "ax" in arch.regs
    assert "cs" in arch.regs


def test_disassembly_analysis_and_llil_for_known_instructions() -> None:
    arch = Intel8086()

    # nop
    text, length = arch.get_instruction_text(b"\x90", BASE)
    assert length == 1
    assert "nop" in _render_text(text).lower()

    info = arch.get_instruction_info(b"\x90", BASE)
    assert info is not None
    assert info.length == 1

    il = MockLowLevelILFunction(arch)
    ll_len = arch.get_instruction_low_level_il(b"\x90", BASE, il)
    assert ll_len == 1
    assert il.ils

    # je short +2
    info2 = arch.get_instruction_info(b"\x74\x02", BASE)
    assert info2 is not None
    assert len(info2.branches) == 2


def test_branch_patch_helpers_for_conditional_jump() -> None:
    arch = Intel8086()
    instr = b"\x74\x02"  # je +2

    assert arch.is_always_branch_patch_available(instr, BASE)
    patched_always = arch.always_branch(instr, BASE)
    assert patched_always[0] == 0xEB

    assert arch.is_invert_branch_patch_available(instr, BASE)
    patched_invert = arch.invert_branch(instr, BASE)
    assert patched_invert[0] == (instr[0] ^ 0x01)


def test_convert_to_nop_preserves_length() -> None:
    arch = Intel8086()
    data = b"\x90\x74\x02\xC3"
    assert arch.convert_to_nop(data, BASE) == b"\x90" * len(data)
