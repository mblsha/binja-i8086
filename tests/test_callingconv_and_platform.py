from __future__ import annotations

import importlib

import binaryninja as bn


def test_calling_conventions_registered_on_8086() -> None:
    # Ensure architecture is registered first.
    import binja_i8086.architecture  # noqa: F401
    import binja_i8086.callingconv  # noqa: F401

    arch = bn.Architecture["8086"]
    names = set(arch.calling_conventions.keys())

    assert {"default", "regparm", "regcall", "cdecl", "pascal"}.issubset(names)
    assert arch.default_calling_convention.name == "regparm"


def test_calling_conventions_registered_on_8086_vanilla() -> None:
    import binja_i8086.architecture  # noqa: F401
    import binja_i8086.callingconv  # noqa: F401

    arch = bn.Architecture["8086-vanilla"]
    names = set(arch.calling_conventions.keys())

    assert {"default", "regparm", "regcall", "cdecl", "pascal"}.issubset(names)
    assert arch.default_calling_convention.name == "regparm"


def test_intel8086_callconv_handles_invalid_incoming_regs() -> None:
    import binja_i8086.architecture  # noqa: F401
    import binja_i8086.callingconv as callingconv

    arch = bn.Architecture["8086"]
    cc = callingconv.Intel8086CallingConvention(arch, "test")

    assert cc._has_arch_reg("ax") is True
    assert cc._has_arch_reg("invalid") is False

    unknown = cc.perform_get_incoming_reg_value("invalid", None)
    assert "Undetermined" in repr(unknown)


def test_platform_defaults_use_regparm_when_available() -> None:
    import binja_i8086.architecture  # noqa: F401
    import binja_i8086.callingconv  # noqa: F401
    import binja_i8086.platform as platform_mod

    # Re-import to make sure defaulting code runs with current registry.
    importlib.reload(platform_mod)

    dos = bn.Platform["dos-8086"]
    assert dos.default_calling_convention is not None
    assert dos.default_calling_convention.name == "regparm"
    assert dos.cdecl_calling_convention is not None
    assert dos.cdecl_calling_convention.name == "cdecl"
