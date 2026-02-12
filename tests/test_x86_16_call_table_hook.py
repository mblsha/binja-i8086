from __future__ import annotations

from binja_i8086 import mc
from binja_i8086 import architecture as arch_mod


def test_x86_16_hook_matches_cs_call_jmp_table_patterns() -> None:
    hook_cls = getattr(arch_mod, "X86_16CallTableHook", None)
    if hook_cls is None:
        # Test environment without ArchitectureHook support.
        return

    decoded_call = mc.decode(bytes.fromhex("2eff160430"), 0x198FC)
    decoded_jmp = mc.decode(bytes.fromhex("ff260430"), 0x1A51E)
    decoded_nop = mc.decode(bytes.fromhex("90"), 0x1234)

    assert hook_cls._should_use_custom_lift(decoded_call)
    assert hook_cls._should_use_custom_lift(decoded_jmp)
    assert not hook_cls._should_use_custom_lift(decoded_nop)
