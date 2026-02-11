from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ImportError, ValueError):
        return False


if not _running_inside_binary_ninja():
    os.environ.setdefault("FORCE_BINJA_MOCK", "1")

from binja_test_mocks import binja_api  # noqa: F401  # Must be imported first
from binja_test_mocks import mock_llil

import binaryninja as bn


# Match 8086 plugin IL suffix expectations (byte/word/linear/dword).
mock_llil.set_size_lookup(
    {1: ".b", 2: ".w", 3: ".l", 4: ".d", 8: ".q"},
    {"b": 1, "w": 2, "l": 3, "d": 4, "q": 8},
)


def _install_variable_shim() -> None:
    if hasattr(bn, "variable"):
        return

    variable_mod = types.ModuleType("binaryninja.variable")

    class UndeterminedValue:
        def __repr__(self) -> str:
            return "Undetermined()"

    def Undetermined() -> UndeterminedValue:  # noqa: N802
        return UndeterminedValue()

    variable_mod.Undetermined = Undetermined  # type: ignore[attr-defined]
    bn.variable = variable_mod  # type: ignore[attr-defined]
    sys.modules["binaryninja.variable"] = variable_mod


def _install_enum_shims() -> None:
    enums = bn.enums

    # binja-i8086 helper token rendering expects these names.
    if not hasattr(enums.InstructionTextTokenType, "OpcodeToken"):
        setattr(
            enums.InstructionTextTokenType,
            "OpcodeToken",
            enums.InstructionTextTokenType.InstructionToken,
        )
    if not hasattr(enums.InstructionTextTokenType, "CodeRelativeAddressToken"):
        setattr(
            enums.InstructionTextTokenType,
            "CodeRelativeAddressToken",
            enums.InstructionTextTokenType.PossibleAddressToken,
        )

    if not hasattr(enums, "RegisterValueType"):
        class RegisterValueType:
            ConstantValue = 1

        enums.RegisterValueType = RegisterValueType  # type: ignore[attr-defined]

    # i8086 plugin expects OddParityFlagRole.
    if not hasattr(enums.FlagRole, "OddParityFlagRole"):
        setattr(
            enums.FlagRole,
            "OddParityFlagRole",
            getattr(enums.FlagRole, "SpecialFlagRole", getattr(enums.FlagRole, "CarryFlagRole")),
        )

    if not hasattr(enums.BranchType, "SystemCall"):
        setattr(
            enums.BranchType,
            "SystemCall",
            getattr(enums.BranchType, "CallDestination", enums.BranchType.UnresolvedBranch),
        )

    # Binary view code marks code/data contents via segment flags.
    if not hasattr(enums.SegmentFlag, "SegmentContainsCode"):
        setattr(enums.SegmentFlag, "SegmentContainsCode", 0)
    if not hasattr(enums.SegmentFlag, "SegmentContainsData"):
        setattr(enums.SegmentFlag, "SegmentContainsData", 0)


def _install_platform_shim() -> None:
    if hasattr(bn, "Platform"):
        return

    class _PlatformMeta(type):
        _registry: dict[str, Any] = {}

        def __iter__(cls):
            return iter(cls._registry.values())

        def __class_getitem__(cls, name: str):
            return cls._registry[name]

        def __getitem__(cls, name: str):
            return cls._registry[name]

    class Platform(metaclass=_PlatformMeta):
        name = ""

        def __init__(self, arch=None):
            self.arch = arch
            self.default_calling_convention = None
            self.cdecl_calling_convention = None

        def register(self, name: str) -> None:
            # Binary Ninja exposes both the registered short name and the
            # platform class name (e.g. "dos-8086") for lookups.
            if isinstance(name, str) and name:
                type(self)._registry[name] = self
            canonical = getattr(type(self), "name", None)
            if isinstance(canonical, str) and canonical:
                type(self)._registry[canonical] = self
            self.name = name

    bn.Platform = Platform  # type: ignore[attr-defined]


def _install_architecture_callingconv_shim() -> None:
    arch_cls = bn.Architecture
    if getattr(arch_cls, "_binja_i8086_cc_patch", False):
        return

    def register(cls) -> None:
        name = getattr(cls, "name", None)
        if not name:
            raise RuntimeError("Architecture subclass must define a non-empty name")
        inst = cls()
        if not hasattr(inst, "calling_conventions"):
            inst.calling_conventions = {}
        cls._registry[name] = inst

    def register_calling_convention(self, calling_convention: Any) -> None:
        cc_name = getattr(calling_convention, "name", None)
        if not isinstance(cc_name, str) or not cc_name:
            return
        if not hasattr(self, "calling_conventions"):
            self.calling_conventions = {}
        self.calling_conventions[cc_name] = calling_convention

    arch_cls.register = classmethod(register)
    arch_cls.register_calling_convention = register_calling_convention
    arch_cls._binja_i8086_cc_patch = True


def _install_binaryview_shim() -> None:
    bv_cls = bn.binaryview.BinaryView
    if getattr(bv_cls, "_binja_i8086_bv_patch", False):
        return

    def __init__(self, file_obj=None, data_view=None):
        if data_view is None and hasattr(file_obj, "read"):
            data_view = file_obj
            file_obj = getattr(file_obj, "file", None)

        if file_obj is None:
            file_obj = types.SimpleNamespace(filename="mock.bin")
        elif not hasattr(file_obj, "filename"):
            file_obj = types.SimpleNamespace(filename=str(file_obj))

        self.file = file_obj
        self.parent_view = data_view if data_view is not None else self
        self.start = 0
        try:
            self.end = len(self.parent_view)
        except Exception:
            self.end = 0

        self._segments = []
        self._sections = []
        self._navigations = []

    def add_auto_segment(self, start, length, data_offset, data_length, flags):
        self._segments.append(
            {
                "start": int(start),
                "length": int(length),
                "data_offset": int(data_offset),
                "data_length": int(data_length),
                "flags": flags,
            }
        )

    def add_auto_section(self, name, start, length, semantics):
        self._sections.append(
            {
                "name": str(name),
                "start": int(start),
                "length": int(length),
                "semantics": semantics,
            }
        )

    def navigate(self, view_name, addr):
        self._navigations.append((str(view_name), int(addr)))

    @property
    def entry_point(self):
        if hasattr(self, "perform_get_entry_point"):
            return int(self.perform_get_entry_point())
        return 0

    bv_cls.__init__ = __init__
    bv_cls.add_auto_segment = add_auto_segment
    bv_cls.add_auto_section = add_auto_section
    bv_cls.navigate = navigate
    bv_cls.entry_point = entry_point
    bv_cls._binja_i8086_bv_patch = True

    if not hasattr(bn, "BinaryView"):
        bn.BinaryView = bv_cls  # type: ignore[attr-defined]


def _install_llil_shim() -> None:
    llil_cls = bn.lowlevelil.LowLevelILFunction
    if getattr(llil_cls, "_binja_i8086_llil_patch", False):
        return

    if not hasattr(llil_cls, "temp_reg_count"):

        @property
        def temp_reg_count(self):  # type: ignore[override]
            # Match BN's monotonically increasing temp register allocator.
            current = getattr(self, "_temp_reg_count", 0)
            self._temp_reg_count = current + 1
            return current

        llil_cls.temp_reg_count = temp_reg_count

    def _add_method(method_name: str, op_name: str, sized: bool):
        if hasattr(llil_cls, method_name):
            return

        if sized:

            def _method(self, size, *ops, flags=None):
                return self._op(op_name, size, *ops, flags=flags)

        else:

            def _method(self, *ops, flags=None):
                return self._op(op_name, None, *ops, flags=flags)

        setattr(llil_cls, method_name, _method)

    if not hasattr(llil_cls, "_op"):

        def _llil_op(self, name: str, size: int | None, *ops: Any, flags: Any | None = None):
            from types import SimpleNamespace

            opname = f"LLIL_{name}"
            return self.expr(SimpleNamespace(name=opname), *ops, size=size, flags=flags)

        llil_cls._op = _llil_op

    _add_method("undefined", "UNDEF", False)
    _add_method("breakpoint", "BP", False)
    _add_method("call_stack_adjust", "CALL_STACK_ADJUST", False)
    _add_method("add_carry", "ADC", True)
    _add_method("sub_borrow", "SBB", True)
    _add_method("flag_bit", "FLAG_BIT", True)
    _add_method("test_bit", "TEST_BIT", True)
    _add_method("reg_split", "REG_SPLIT", True)
    _add_method("low_part", "LOW_PART", True)
    _add_method("set_reg_split", "SET_REG_SPLIT", True)
    _add_method("sign_extend", "SX", True)
    _add_method("neg_expr", "NEG", True)
    _add_method("not_expr", "NOT", True)
    _add_method("div_unsigned", "DIVU", True)
    _add_method("mod_unsigned", "MODU", True)
    _add_method("mod_signed", "MODS", True)
    _add_method("arith_shift_right", "ASR", True)

    llil_cls._binja_i8086_llil_patch = True


def _install_ilregister_shim() -> None:
    ilreg_cls = bn.lowlevelil.ILRegister
    if getattr(ilreg_cls, "_binja_i8086_patch", False):
        return

    orig_init = ilreg_cls.__init__

    def __init__(self, *args, **kwargs):
        # Real BN accepts ILRegister(arch, index); binja-test-mocks currently
        # uses ILRegister(index).
        if len(args) == 2 and not kwargs:
            _arch, index = args
            return orig_init(self, index)
        return orig_init(self, *args, **kwargs)

    ilreg_cls.__init__ = __init__
    ilreg_cls._binja_i8086_patch = True


_install_variable_shim()
_install_enum_shims()
_install_platform_shim()
_install_architecture_callingconv_shim()
_install_binaryview_shim()
_install_llil_shim()
_install_ilregister_shim()


def _load_plugin_package() -> None:
    pkg_name = "binja_i8086"
    if pkg_name in sys.modules:
        return

    init_py = REPO_ROOT / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        init_py,
        submodule_search_locations=[str(REPO_ROOT)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load plugin package from {init_py}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)


_load_plugin_package()
