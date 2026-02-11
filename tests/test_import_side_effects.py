from __future__ import annotations

import importlib


def test_package_import_registers_architecture_and_dos_platform() -> None:
    pkg = importlib.import_module("binja_i8086")
    assert pkg is not None

    import binaryninja as bn

    arch = bn.Architecture["8086"]
    assert arch is not None

    dos = bn.Platform["dos-8086"]
    assert dos is not None
