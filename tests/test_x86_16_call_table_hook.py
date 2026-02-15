from __future__ import annotations

from binja_i8086 import mc
from binja_i8086 import architecture as arch_mod


def test_x86_16_hook_matches_cs_call_jmp_table_patterns() -> None:
    hook_cls = getattr(arch_mod, "X86_16CallTableHook", None)
    if hook_cls is None:
        # Test environment without ArchitectureHook support.
        return

    decoded_table_call = mc.decode(bytes.fromhex("2eff160430"), 0x198FC)
    decoded_table_jmp = mc.decode(bytes.fromhex("ff260430"), 0x1A51E)
    decoded_non_table_call = mc.decode(bytes.fromhex("ff17"), 0x1234)
    decoded_nop = mc.decode(bytes.fromhex("90"), 0x1234)

    assert hook_cls._should_use_custom_lift(decoded_table_call)
    assert hook_cls._should_use_custom_lift(decoded_table_jmp)
    assert not hook_cls._should_use_custom_lift(decoded_non_table_call)
    assert not hook_cls._should_use_custom_lift(decoded_nop)


def test_x86_16_hook_respects_cs_table_lift_setting() -> None:
    hook_cls = getattr(arch_mod, "X86_16CallTableHook", None)
    if hook_cls is None:
        return

    decoded_table_call = mc.decode(bytes.fromhex("2eff160430"), 0x198FC)

    class FakeArch:
        cs_table_lift = True

    arch = FakeArch()
    assert hook_cls._should_use_custom_lift(decoded_table_call, arch)
    arch.cs_table_lift = False
    assert not hook_cls._should_use_custom_lift(decoded_table_call, arch)
