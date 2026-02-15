from binaryninja import Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo

try:
    from binaryninja import ArchitectureHook
except Exception:
    ArchitectureHook = None
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition, LowLevelILOperation
from binaryninja.types import Type
from binaryninja.log import log_error

try:
    from . import mc
except ImportError:
    import mc


__all__ = ['Intel8086', 'Intel8086Vanilla']

RET_PASS_FLAGS_BY_ARCH = {
    "8086": True,
    "8086-vanilla": True,
}

CS_TABLE_LIFT_BY_ARCH = {
    "8086": True,
    "8086-vanilla": False,
    "x86_16": True,
}

RET_STATUS_FLAGS = ("c", "p", "a", "z", "s", "o")
RET_FLAG_SHADOW_REGS = {
    "c": "rc",
    "p": "rp",
    "a": "ra",
    "z": "rz",
    "s": "rs",
    "o": "ro",
}


class Intel8086(Architecture):
    name = "8086"
    endianness = Endianness.LittleEndian

    default_int_size = 2
    address_size = 3

    stack_pointer = 'sp'
    regs = {
        # General
        'ax': RegisterInfo('ax', 2, 0),
            'al': RegisterInfo('ax', 1, 0),
            'ah': RegisterInfo('ax', 1, 1),
        'cx': RegisterInfo('cx', 2, 0),
            'cl': RegisterInfo('cx', 1, 0),
            'ch': RegisterInfo('cx', 1, 1),
        'bx': RegisterInfo('bx', 2, 0),
            'bl': RegisterInfo('bx', 1, 0),
            'bh': RegisterInfo('bx', 1, 1),
        'dx': RegisterInfo('dx', 2, 0),
            'dl': RegisterInfo('dx', 1, 0),
            'dh': RegisterInfo('dx', 1, 1),
        'sp': RegisterInfo('sp', 2),
        'bp': RegisterInfo('bp', 2),
        'si': RegisterInfo('si', 2),
        'di': RegisterInfo('di', 2),
        # Segment
        'cs': RegisterInfo('cs', 2),
        'ds': RegisterInfo('ds', 2),
        'es': RegisterInfo('es', 2),
        'ss': RegisterInfo('ss', 2),
        # Instruction pointer
        'ip': RegisterInfo('ip', 2),
        # Shadow registers used to pass status flags through call/ret edges.
        'rc': RegisterInfo('rc', 1),
        'rp': RegisterInfo('rp', 1),
        'ra': RegisterInfo('ra', 1),
        'rz': RegisterInfo('rz', 1),
        'rs': RegisterInfo('rs', 1),
        'ro': RegisterInfo('ro', 1),
    }
    flags = [
        # Status
        'c', # carry
        'p', # parity
        'a', # aux carry
        'z', # zero
        's', # sign
        'o', # overflow
        # Control
        'i', # interrupt
        'd', # direction
        't', # trap
    ]
    flag_roles = {
        'c': FlagRole.CarryFlagRole,
        'p': FlagRole.OddParityFlagRole,
        'a': FlagRole.HalfCarryFlagRole,
        'z': FlagRole.ZeroFlagRole,
        's': FlagRole.NegativeSignFlagRole,
        't': FlagRole.SpecialFlagRole,
        'i': FlagRole.SpecialFlagRole,
        'd': FlagRole.SpecialFlagRole,
        'o': FlagRole.OverflowFlagRole,
    }
    flag_write_types = [
        '',
        '*',
        '!c',
        'co',
    ]
    flags_written_by_flag_write_type = {
        '*':  ['c', 'p', 'a', 'z', 's', 'o'],
        '!c': ['p', 'a', 'z', 's', 'o'],
        'co': ['c', 'o'],
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E:   ['z'],
        LowLevelILFlagCondition.LLFC_NE:  ['z'],
        LowLevelILFlagCondition.LLFC_SLT: ['s', 'o'],
        LowLevelILFlagCondition.LLFC_ULT: ['c'],
        LowLevelILFlagCondition.LLFC_SLE: ['z', 's', 'o'],
        LowLevelILFlagCondition.LLFC_ULE: ['c', 'z'],
        LowLevelILFlagCondition.LLFC_SGE: ['s', 'o'],
        LowLevelILFlagCondition.LLFC_UGE: ['c'],
        LowLevelILFlagCondition.LLFC_SGT: ['z', 's', 'o'],
        LowLevelILFlagCondition.LLFC_UGT: ['c', 'z'],
        LowLevelILFlagCondition.LLFC_NEG: ['s'],
        LowLevelILFlagCondition.LLFC_POS: ['s'],
        LowLevelILFlagCondition.LLFC_O:   ['o'],
        LowLevelILFlagCondition.LLFC_NO:  ['o'],
    }

    intrinsics = {
        'outb': IntrinsicInfo([Type.int(2), Type.int(1)], []),
        'outw': IntrinsicInfo([Type.int(2), Type.int(2)], []),
        'inb': IntrinsicInfo([Type.int(1)], [Type.int(2)]),
        'inw': IntrinsicInfo([Type.int(2)], [Type.int(2)]),
    }

    ret_status_flags = RET_STATUS_FLAGS
    ret_flag_shadow_regs = RET_FLAG_SHADOW_REGS
    ret_pass_flags = False
    cs_table_lift = True

    def __init__(self):
        super().__init__()
        self.ret_pass_flags = RET_PASS_FLAGS_BY_ARCH.get(self.name, False)
        self.cs_table_lift = CS_TABLE_LIFT_BY_ARCH.get(self.name, True)

    def _flag_expr_width(self, size):
        if isinstance(size, int) and size > 0:
            return size
        return 1

    def _coerce_reg_operand(self, il, size, operand):
        candidates = []
        seen = set()

        def push(value):
            key = id(value)
            if key in seen:
                return
            seen.add(key)
            candidates.append(value)

        push(operand)
        for attr in ("name", "reg", "register", "index"):
            try:
                value = getattr(operand, attr, None)
            except Exception:
                value = None
            if value is not None:
                push(value)

        while candidates:
            candidate = candidates.pop(0)
            if candidate is None:
                continue
            if isinstance(candidate, str):
                try:
                    return il.reg(size, candidate)
                except Exception:
                    continue
            if isinstance(candidate, int):
                try:
                    return il.reg(size, candidate)
                except Exception:
                    continue
            for attr in ("name", "reg", "register", "index"):
                try:
                    nested = getattr(candidate, attr, None)
                except Exception:
                    nested = None
                if nested is not None:
                    push(nested)
        return None

    def _normalize_flag_operand(self, il, size, operand):
        # Some callback paths pass raw ILRegister operands; arithmetic builders
        # require expression operands, so convert register descriptors to `reg`.
        try:
            if type(operand).__name__ == "ILRegister":
                reg_expr = self._coerce_reg_operand(il, size, operand)
                if reg_expr is not None:
                    return reg_expr
        except Exception:
            pass
        return operand

    def _calc_flag_result_expr(self, op, size, operands, il):
        w = self._flag_expr_width(size)
        if not isinstance(operands, (tuple, list)):
            return None
        if op in (LowLevelILOperation.LLIL_SET_REG, LowLevelILOperation.LLIL_STORE):
            if len(operands) >= 2:
                return self._normalize_flag_operand(il, w, operands[1])
            return None
        if len(operands) < 2:
            return None
        lhs = self._normalize_flag_operand(il, w, operands[0])
        rhs = self._normalize_flag_operand(il, w, operands[1])
        if op == LowLevelILOperation.LLIL_ADD:
            return il.add(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_SUB:
            return il.sub(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_ADC and len(operands) >= 3:
            carry = self._normalize_flag_operand(il, 1, operands[2])
            return il.add_carry(w, lhs, rhs, carry)
        if op == LowLevelILOperation.LLIL_SBB and len(operands) >= 3:
            borrow = self._normalize_flag_operand(il, 1, operands[2])
            return il.sub_borrow(w, lhs, rhs, borrow)
        if op == LowLevelILOperation.LLIL_AND:
            return il.and_expr(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_OR:
            return il.or_expr(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_XOR:
            return il.xor_expr(w, lhs, rhs)
        return None

    def _calc_parity_flag_expr(self, op, size, operands, il):
        result = self._calc_flag_result_expr(op, size, operands, il)
        if result is None:
            return None
        low8 = il.low_part(1, result)
        parity_xor = il.const(1, 0)
        for bit in range(8):
            bit_expr = il.test_bit(1, low8, il.const(1, bit))
            parity_xor = il.xor_expr(1, parity_xor, bit_expr)
        # PF=1 for even parity of low 8 bits.
        return il.compare_equal(1, parity_xor, il.const(1, 0))

    def _calc_aux_carry_flag_expr(self, op, size, operands, il):
        w = self._flag_expr_width(size)
        if not isinstance(operands, (tuple, list)) or len(operands) < 2:
            return None
        lhs = self._normalize_flag_operand(il, w, operands[0])
        rhs = self._normalize_flag_operand(il, w, operands[1])

        if op in (LowLevelILOperation.LLIL_AND, LowLevelILOperation.LLIL_OR, LowLevelILOperation.LLIL_XOR):
            # AF is undefined for logical ops on x86; use a stable 0 to avoid
            # polluting MLIL/HLIL with "unimplemented" pseudo-ops.
            return il.const(1, 0)

        if op == LowLevelILOperation.LLIL_ADD:
            result = il.add(w, lhs, rhs)
        elif op == LowLevelILOperation.LLIL_SUB:
            result = il.sub(w, lhs, rhs)
        elif op == LowLevelILOperation.LLIL_ADC and len(operands) >= 3:
            carry = self._normalize_flag_operand(il, 1, operands[2])
            result = il.add_carry(w, lhs, rhs, carry)
        elif op == LowLevelILOperation.LLIL_SBB and len(operands) >= 3:
            borrow = self._normalize_flag_operand(il, 1, operands[2])
            result = il.sub_borrow(w, lhs, rhs, borrow)
        else:
            return None

        # AF is bit4 carry/borrow. Works for both add/sub families.
        nibble = il.and_expr(
            w,
            il.xor_expr(w, il.xor_expr(w, lhs, rhs), result),
            il.const(w, 0x10),
        )
        return il.compare_not_equal(w, nibble, il.const(w, 0))

    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        try:
            if flag == "p":
                parity = self._calc_parity_flag_expr(op, size, operands, il)
                if parity is not None:
                    return parity
            if flag == "a":
                aux = self._calc_aux_carry_flag_expr(op, size, operands, il)
                if aux is not None:
                    return aux
        except Exception:
            # Never let custom flag lowering break BN analysis.
            pass
        try:
            return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)
        except Exception:
            # Last-resort fallback to avoid aborting analysis on unexpected core API
            # operand shapes.
            return il.undefined()

    def get_instruction_info(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            info = InstructionInfo()
            decoded.analyze(info, addr)
            return info

    def get_instruction_text(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            encoded = data[:decoded.total_length()]
            recoded = mc.encode(decoded, addr)
            if encoded != recoded:
                log_error("Instruction roundtrip error")
                log_error("".join([str(x) for x in decoded.render(addr)]))
                log_error("Orig: {}".format(encoded.hex()))
                log_error("New:  {}".format(recoded.hex()))

            return decoded.render(addr), decoded.total_length()

    def get_instruction_low_level_il(self, data, addr, il):
        decoded = mc.decode(data, addr)
        if decoded:
            decoded.lift(il, addr)
            return decoded.total_length()

    def convert_to_nop(self, data, addr):
        return b'\x90' * len(data)

    def is_always_branch_patch_available(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            return isinstance(decoded, mc.instr.jmp.JmpCond)

    def always_branch(self, data, addr):
        branch = mc.decode(data, addr)
        branch = branch.to_always()
        return mc.encode(branch, addr)

    def is_invert_branch_patch_available(self, data, addr):
        decoded = mc.decode(data, addr)
        if decoded:
            return isinstance(decoded, mc.instr.jmp.JmpCond)

    def invert_branch(self, data, addr):
        branch = mc.decode(data, addr)
        branch = branch.to_inverted()
        return mc.encode(branch, addr)

class Intel8086Vanilla(Intel8086):
    name = "8086-vanilla"


Intel8086.register()
Intel8086Vanilla.register()


if ArchitectureHook is not None:

    class X86_16CallTableHook(ArchitectureHook):
        """Lift x86_16 call/jmp cs:[disp16] table entries through i8086 helpers."""

        def __init__(self, base_arch):
            super().__init__(base_arch)

        @staticmethod
        def _custom_lift_enabled(arch):
            if arch is None:
                return True
            try:
                explicit = getattr(arch, "__dict__", {}).get("cs_table_lift", None)
                if explicit is not None:
                    return bool(explicit)
            except Exception:
                pass
            try:
                value = getattr(arch, "cs_table_lift", None)
                if value is not None:
                    return bool(value)
            except Exception:
                pass
            return CS_TABLE_LIFT_BY_ARCH.get(getattr(arch, "name", ""), True)

        @staticmethod
        def _is_cs_table_form(instr):
            if not isinstance(instr, (mc.instr.call.CallNearRM, mc.instr.jmp.JmpNearRM)):
                return False
            try:
                if instr._mod_bits() != 0b00 or instr._reg_mem_bits() != 0b110:
                    return False
                return instr.segment() == "cs"
            except Exception:
                return False

        @classmethod
        def _should_use_custom_lift(cls, decoded, arch=None):
            if decoded is None:
                return False
            if not cls._custom_lift_enabled(arch):
                return False

            try:
                if cls._is_cs_table_form(decoded):
                    return True

                if isinstance(decoded, mc.instr.seg.Segment):
                    nxt = getattr(decoded, "next", None)
                    if cls._is_cs_table_form(nxt):
                        return True
            except Exception:
                return False

            return False

        @staticmethod
        def _attach_view_if_missing(il):
            try:
                if getattr(il, "view", None) is not None:
                    return
            except Exception:
                return

            try:
                source_function = getattr(il, "source_function", None)
                if source_function is not None:
                    view = getattr(source_function, "view", None)
                    if view is not None:
                        il.view = view
            except Exception:
                pass

        def get_instruction_low_level_il(self, data, addr, il):
            decoded = mc.decode(data, addr)
            if self._should_use_custom_lift(decoded, self.base_arch):
                try:
                    self._attach_view_if_missing(il)
                    decoded.lift(il, addr)
                    return decoded.total_length()
                except Exception:
                    # Fall back to core lifting for safety.
                    pass

            return super().get_instruction_low_level_il(data, addr, il)


_x86_16_call_table_hook = None
if ArchitectureHook is not None:
    try:
        _x86_16_arch = Architecture["x86_16"]
        try:
            if getattr(_x86_16_arch, "__dict__", {}).get("cs_table_lift", None) is None:
                _x86_16_arch.cs_table_lift = CS_TABLE_LIFT_BY_ARCH.get("x86_16", True)
        except Exception:
            pass
        _x86_16_call_table_hook = X86_16CallTableHook(_x86_16_arch)
        _x86_16_call_table_hook.register()
    except Exception:
        _x86_16_call_table_hook = None
