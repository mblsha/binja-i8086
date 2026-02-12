from __future__ import annotations

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockFlag, MockLabel, MockLLIL, mllil, mreg

from binja_i8086.architecture import Intel8086


STATUS_FLAGS = ("c", "p", "a", "z", "s", "o")
SHADOW_REGS = {
    "c": "rc",
    "p": "rp",
    "a": "ra",
    "z": "rz",
    "s": "rs",
    "o": "ro",
}


def _lift_to_llil(arch: Intel8086, data: bytes, addr: int = 0x1000) -> list[MockLLIL]:
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = addr  # type: ignore[attr-defined]
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length is not None and length > 0
    return [node for node in il if not isinstance(node, MockLabel)]


def _expected_flag_restores() -> list[MockLLIL]:
    return [
        mllil("SET_FLAG", [MockFlag(flag), mllil("REG.b", [mreg(SHADOW_REGS[flag])])])
        for flag in STATUS_FLAGS
    ]


def _expected_flag_shadows() -> list[MockLLIL]:
    return [
        mllil("SET_REG.b", [mreg(SHADOW_REGS[flag]), mllil("FLAG", [MockFlag(flag)])])
        for flag in STATUS_FLAGS
    ]


def test_ret_pass_flags_metadata_and_shadow_regs() -> None:
    arch = Intel8086()
    assert arch.ret_pass_flags is True
    assert tuple(arch.ret_status_flags) == STATUS_FLAGS
    assert arch.ret_flag_shadow_regs == SHADOW_REGS
    for reg_name in SHADOW_REGS.values():
        assert reg_name in arch.regs
        assert arch.regs[reg_name].size == 1


def test_near_call_and_ret_propagate_status_flags() -> None:
    arch = Intel8086()

    call_llil = _lift_to_llil(arch, b"\xE8\x00\x00")
    assert call_llil == [
        mllil("CALL", [mllil("CONST.l", [0x1003])]),
        *_expected_flag_restores(),
    ]

    ret_llil = _lift_to_llil(arch, b"\xC3")
    assert ret_llil == [
        *_expected_flag_shadows(),
        mllil("RET", [mllil("POP.w", [])]),
    ]


def test_far_call_and_ret_include_flag_propagation() -> None:
    arch = Intel8086()

    call_far_llil = _lift_to_llil(arch, b"\x9A\x34\x12\x78\x56")
    assert call_far_llil[-len(STATUS_FLAGS) :] == _expected_flag_restores()

    ret_far_llil = _lift_to_llil(arch, b"\xCB")
    assert ret_far_llil[: len(STATUS_FLAGS)] == _expected_flag_shadows()
    assert ret_far_llil[-1].op == "RET"


def test_ret_pass_flags_can_be_disabled_per_arch_instance() -> None:
    arch = Intel8086()
    arch.ret_pass_flags = False

    call_llil = _lift_to_llil(arch, b"\xE8\x00\x00")
    assert call_llil == [mllil("CALL", [mllil("CONST.l", [0x1003])])]

    ret_llil = _lift_to_llil(arch, b"\xC3")
    assert ret_llil == [mllil("RET", [mllil("POP.w", [])])]


def test_ret_pass_flags_fallback_for_x86_16_core_style_arch() -> None:
    arch = Intel8086()
    arch.name = "x86_16"
    # Simulate a CoreArchitecture-like object where plugin attrs are absent.
    arch.__dict__.pop("ret_pass_flags", None)

    call_llil = _lift_to_llil(arch, b"\xE8\x00\x00")
    assert call_llil == [
        mllil("CALL", [mllil("CONST.l", [0x1003])]),
        *_expected_flag_restores(),
    ]

    ret_llil = _lift_to_llil(arch, b"\xC3")
    assert ret_llil == [
        *_expected_flag_shadows(),
        mllil("RET", [mllil("POP.w", [])]),
    ]
