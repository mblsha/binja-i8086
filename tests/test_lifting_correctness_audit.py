from __future__ import annotations

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockLabel

from binja_i8086.architecture import Intel8086
from binja_i8086 import mc


def _lift(data: bytes, addr: int = 0x1000):
    arch = Intel8086()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = addr  # type: ignore[attr-defined]
    length = arch.get_instruction_low_level_il(data, addr, il)
    assert length is not None and length > 0
    return length, [node for node in il if not isinstance(node, MockLabel)]


def _joined(nodes) -> str:
    return " | ".join(str(node) for node in nodes).lower()


def test_pop_rm_pops_and_stores_instead_of_pushing() -> None:
    length, nodes = _lift(bytes.fromhex("8f07"))
    assert length == 2
    assert [node.op for node in nodes] == [
        "SET_REG.w",
        "SET_REG.w",
        "STORE.b",
        "STORE.b",
    ]
    assert "pop.w" in _joined(nodes)
    assert "push" not in _joined(nodes)


def test_cmc_boolean_complements_carry() -> None:
    _, nodes = _lift(bytes.fromhex("f5"))
    text = _joined(nodes)
    assert "xor.b" in text
    assert "const.b', ops=[1]" in text
    assert "neg" not in text


def test_word_port_immediate_is_always_one_byte() -> None:
    length, nodes = _lift(bytes.fromhex("e53490"))
    assert length == 2
    assert "inw" in _joined(nodes)
    assert "ops=[52]" in _joined(nodes)
    assert "36916" not in _joined(nodes)


def test_word_string_ops_step_indices_by_two() -> None:
    _, nodes = _lift(bytes.fromhex("a5"))
    index_writes = [
        node for node in nodes
        if node.op == "SET_REG.w"
        and getattr(node.ops[0], "name", "").lower() in ("si", "di")
    ]
    assert index_writes
    assert all("ops=[2]" in str(node) for node in index_writes)


def test_rep_prechecks_cx_and_repe_checks_zf_after_body() -> None:
    length, nodes = _lift(bytes.fromhex("f3a7"))
    assert length == 2
    assert nodes[0].op == "NOP"
    assert nodes[1].op == "IF"
    text = _joined(nodes)
    assert "cmp_ne.w" in text
    assert "and.b" in text
    assert "flag(name='z')" in text


def test_nested_prefixes_have_full_length_and_last_segment_wins() -> None:
    for blob in (bytes.fromhex("26f3a4"), bytes.fromhex("f326a4")):
        length, nodes = _lift(blob)
        assert length == 3
        assert "es" in _joined(nodes)

    length, nodes = _lift(bytes.fromhex("2e268b07"))
    assert length == 4
    text = _joined(nodes)
    assert "es" in text
    assert "cs" not in text


def test_last_repeat_prefix_controls_comparison_loop() -> None:
    _, repe_nodes = _lift(bytes.fromhex("f2f3a6"))
    _, repne_nodes = _lift(bytes.fromhex("f3f2a6"))
    assert "ops=[1]" in str(repe_nodes[-1])
    assert "ops=[0]" in str(repne_nodes[-1])


def test_prefix_address_is_included_in_relative_target() -> None:
    length, nodes = _lift(bytes.fromhex("2eeb00"), 0x1200)
    assert length == 3
    assert "ops=[4611]" in _joined(nodes)  # 0x1203


def test_prefix_and_relative_target_wrap_together_at_ip_boundary() -> None:
    length, nodes = _lift(bytes.fromhex("2eeb00"), 0xFFFF)
    assert length == 3
    assert "ops=[2]" in _joined(nodes)


def test_far_pointer_operands_load_four_wrapped_bytes_from_effective_address() -> None:
    _, nodes = _lift(bytes.fromhex("c41e3412"))  # les bx,[0x1234]
    text = _joined(nodes)
    assert text.count("load.b") == 4
    assert "load.w" not in text and "load.d" not in text


def test_near_indirect_fetch_segment_is_distinct_from_target_cs() -> None:
    _, nodes = _lift(bytes.fromhex("ff17"))
    text = _joined(nodes)
    assert text.count("load.b") == 2
    assert "ds" in text
    assert "cs" in text

    _, override_nodes = _lift(bytes.fromhex("26ff17"))
    override_text = _joined(override_nodes)
    assert "es" in override_text
    assert "cs" in override_text


def test_far_direct_target_wraps_to_twenty_bits() -> None:
    _, nodes = _lift(bytes.fromhex("eaffffffff"))
    assert nodes[-1].op == "JUMP"
    assert "ops=[65519]" in str(nodes[-1])  # FFFF:FFFF -> 0x0FFEF


def test_ret_imm_pops_before_adjust_and_returns_through_cs() -> None:
    _, nodes = _lift(bytes.fromhex("c20400"))
    ops = [node.op for node in nodes]
    pop_index = next(i for i, node in enumerate(nodes) if "pop.w" in str(node).lower())
    sp_index = next(i for i, node in enumerate(nodes) if node.op == "SET_REG.w" and "sp" in str(node).lower())
    assert pop_index < sp_index < ops.index("RET")
    assert "cs" in str(nodes[-1]).lower()


def test_ret_imm_render_emits_binary_ninja_tokens() -> None:
    for blob in (bytes.fromhex("c20400"), bytes.fromhex("ca0400")):
        decoded = mc.decode(blob, 0x1000)
        assert decoded is not None
        assert all(not isinstance(token, tuple) for token in decoded.render(0x1000))


def test_xchg_memory_caches_effective_address_before_register_write() -> None:
    _, nodes = _lift(bytes.fromhex("871f"))  # xchg bx,[bx]
    assert nodes[0].op == "SET_REG.l"
    assert [node.op for node in nodes[-2:]] == ["STORE.b", "STORE.b"]
    assert "temp0" in str(nodes[-1]).lower()
    assert "bx" not in str(nodes[-1]).lower()


def test_mul_div_use_double_precision_and_cache_results() -> None:
    _, mul_nodes = _lift(bytes.fromhex("f6e0"))
    assert "mulu_dp.b{co}" in _joined(mul_nodes)
    assert any(node.op == "SET_REG.w" for node in mul_nodes)
    assert [node.op for node in mul_nodes[-4:]] == ["SET_FLAG"] * 4

    _, imul_nodes = _lift(bytes.fromhex("f7e8"))
    assert "muls_dp.w{co}" in _joined(imul_nodes)
    assert any(node.op == "SET_REG_SPLIT.w" for node in imul_nodes)

    _, div_nodes = _lift(bytes.fromhex("f6f0"))
    div_text = _joined(div_nodes)
    assert "divu_dp.b" in div_text
    assert "modu_dp.b" in div_text
    result_writes = [node for node in div_nodes if node.op == "SET_REG.b"]
    assert len(result_writes) >= 2
    assert "temp1" in str(result_writes[-2]).lower()
    assert "temp2" in str(result_writes[-1]).lower()

    assert [node.op for node in div_nodes[-6:]] == ["SET_FLAG"] * 6


def test_decimal_adjust_preserves_old_al_and_carry_in_distinct_temporaries() -> None:
    for opcode in (b"\x27", b"\x2f"):
        _, nodes = _lift(opcode)
        assert "temp0" in str(nodes[0]).lower()
        assert "temp1" in str(nodes[1]).lower()
        branch_text = _joined(nodes)
        assert "temp0" in branch_text
        assert "temp1" in branch_text


def test_neg_and_shifts_write_the_architecturally_defined_flags() -> None:
    _, neg_nodes = _lift(bytes.fromhex("f6d8"))
    assert "neg.b{*}" in _joined(neg_nodes)

    _, shift_nodes = _lift(bytes.fromhex("d0e0"))
    assert "lsl.b{shift}" in _joined(shift_nodes)
    assert "flag(name='a')" in _joined(shift_nodes)

    _, variable_nodes = _lift(bytes.fromhex("d2e0"))
    assert variable_nodes[0].op == "IF"
    shift_index = next(
        i for i, node in enumerate(variable_nodes)
        if "lsl.b{shift}" in str(node).lower()
    )
    assert shift_index > 0


def test_dec_uses_subtraction_flags_while_preserving_carry() -> None:
    _, nodes = _lift(bytes.fromhex("48"))  # dec ax
    text = _joined(nodes)
    assert "sub.w{!c}" in text
    assert "add.w{!c}" not in text


def test_cwd_uses_word_sized_split_registers() -> None:
    _, nodes = _lift(bytes.fromhex("99"))
    assert nodes == [nodes[0]]
    assert nodes[0].op == "SET_REG_SPLIT.w"


def test_invalid_modrm_forms_lift_as_undefined_with_correct_length() -> None:
    for blob, expected_len in (
        (bytes.fromhex("8dc0"), 2),       # lea ax,ax is invalid
        (bytes.fromhex("8ec8"), 2),       # mov cs,ax is invalid
        (bytes.fromhex("c78e34127856"), 4),  # C7 /1 consumes ModR/M+disp, not imm
    ):
        length, nodes = _lift(blob)
        assert length == expected_len
        assert [node.op for node in nodes] == ["UNDEF"]


def test_original_8086_adjust_and_escape_opcodes_are_lifted() -> None:
    for blob in (b"\x27", b"\x2f", b"\x37", b"\x3f", b"\xd4\x0a", b"\xd5\x0a"):
        length, nodes = _lift(blob)
        assert length == len(blob)
        assert len(nodes) > 1
        assert not (len(nodes) == 1 and nodes[0].op == "UNDEF")

    length, nodes = _lift(bytes.fromhex("d84610"))
    assert length == 3
    assert len(nodes) == 1
    assert "esc" in _joined(nodes)


def test_aam_zero_raises_the_real_type_zero_interrupt() -> None:
    _, nodes = _lift(bytes.fromhex("d400"))
    text = _joined(nodes)
    assert "trap" not in text
    assert text.count("push.w") == 3
    assert text.count("load.b") == 4
    assert nodes[-1].op == "JUMP"


def test_interrupt_saves_state_and_transfers_through_vector() -> None:
    _, nodes = _lift(bytes.fromhex("cd21"))
    text = _joined(nodes)
    assert text.count("push.w") == 3
    assert "flag(name='t')" in text
    assert "flag(name='i')" in text
    assert text.count("load.b") == 4
    assert nodes[-2].op == "SET_REG.w"
    assert nodes[-1].op == "JUMP"


def test_hlt_is_resumable_opaque_operation_not_noreturn() -> None:
    _, nodes = _lift(bytes.fromhex("f4"))
    assert len(nodes) == 1
    assert "hlt" in _joined(nodes)
    assert "no_ret" not in _joined(nodes)


def test_original_pop_cs_and_salc_have_8086_semantics() -> None:
    _, pop_nodes = _lift(bytes.fromhex("0f"), 0x1234)
    pop_text = _joined(pop_nodes)
    assert "pop.w" in pop_text
    assert "set_reg.w" in pop_text
    assert "jump" in pop_text
    assert "cs" in pop_text

    _, salc_nodes = _lift(bytes.fromhex("d6"))
    salc_text = _joined(salc_nodes)
    assert "set_reg.b" in salc_text
    assert "sub.b" in salc_text
    assert "flag(name='c')" in salc_text


def test_original_push_sp_stores_the_post_decrement_value() -> None:
    for blob in (bytes.fromhex("54"), bytes.fromhex("fff4")):
        _, nodes = _lift(blob)
        assert "push.w" in _joined(nodes)
        assert "sub.w" in _joined(nodes)
        assert "ops=[2]" in _joined(nodes)


def test_multibyte_memory_accesses_wrap_each_byte_on_the_a20_bus() -> None:
    _, load_nodes = _lift(bytes.fromhex("a1ffff"))
    load_text = _joined(load_nodes)
    assert load_text.count("load.b") == 2
    assert "load.w" not in load_text
    assert "ops=[1]" in load_text
    assert load_text.count("ops=[1048575]") >= 2

    _, store_nodes = _lift(bytes.fromhex("a3ffff"))
    assert [node.op for node in store_nodes[-2:]] == ["STORE.b", "STORE.b"]
    assert "ops=[1]" in _joined(store_nodes)
