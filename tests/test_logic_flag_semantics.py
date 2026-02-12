from __future__ import annotations

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockFlag, MockLabel, MockLLIL, mllil, mreg

from binja_i8086.architecture import Intel8086


def _lift_to_llil(data: bytes, addr: int = 0x1000) -> list[MockLLIL]:
    arch = Intel8086()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = addr  # type: ignore[attr-defined]
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length is not None and length > 0
    return [node for node in il if not isinstance(node, MockLabel)]


def test_and_acc_imm_uses_noncarry_flag_write_and_clears_cf_of() -> None:
    llil = _lift_to_llil(b"\x24\x7f")  # and al, 0x7f
    assert llil == [
        mllil(
            "SET_REG.b",
            [
                mreg("al"),
                mllil(
                    "AND.b{!c}",
                    [
                        mllil("REG.b", [mreg("al")]),
                        mllil("CONST.b", [0x7F]),
                    ],
                ),
            ],
        ),
        mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
        mllil("SET_FLAG", [MockFlag("o"), mllil("CONST.b", [0])]),
    ]


def test_or_acc_imm_uses_noncarry_flag_write_and_clears_cf_of() -> None:
    llil = _lift_to_llil(b"\x0c\x80")  # or al, 0x80
    assert llil == [
        mllil(
            "SET_REG.b",
            [
                mreg("al"),
                mllil(
                    "OR.b{!c}",
                    [
                        mllil("REG.b", [mreg("al")]),
                        mllil("CONST.b", [0x80]),
                    ],
                ),
            ],
        ),
        mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
        mllil("SET_FLAG", [MockFlag("o"), mllil("CONST.b", [0])]),
    ]


def test_test_rmimm_uses_noncarry_flag_write_and_clears_cf_of() -> None:
    llil = _lift_to_llil(b"\xf6\x44\x06\xf0")  # test byte [si+0x6], 0xf0
    assert llil[0].op == "AND.b{!c}"
    assert llil[1:] == [
        mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
        mllil("SET_FLAG", [MockFlag("o"), mllil("CONST.b", [0])]),
    ]
