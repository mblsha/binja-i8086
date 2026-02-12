from binaryninja import Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition, LowLevelILOperation
from binaryninja.types import Type
from binaryninja.log import log_error

try:
    from . import mc
except ImportError:
    import mc


__all__ = ['Intel8086']

RET_PASS_FLAGS_BY_ARCH = {
    "8086": True,
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

    def __init__(self):
        super().__init__()
        self.ret_pass_flags = RET_PASS_FLAGS_BY_ARCH.get(self.name, False)

    def _flag_expr_width(self, size):
        if isinstance(size, int) and size > 0:
            return size
        return 1

    def _calc_flag_result_expr(self, op, size, operands, il):
        w = self._flag_expr_width(size)
        if not isinstance(operands, (tuple, list)):
            return None
        if op in (LowLevelILOperation.LLIL_SET_REG, LowLevelILOperation.LLIL_STORE):
            if len(operands) >= 2:
                return operands[1]
            return None
        if len(operands) < 2:
            return None
        lhs = operands[0]
        rhs = operands[1]
        if op == LowLevelILOperation.LLIL_ADD:
            return il.add(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_SUB:
            return il.sub(w, lhs, rhs)
        if op == LowLevelILOperation.LLIL_ADC and len(operands) >= 3:
            return il.add_carry(w, lhs, rhs, operands[2])
        if op == LowLevelILOperation.LLIL_SBB and len(operands) >= 3:
            return il.sub_borrow(w, lhs, rhs, operands[2])
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
        lhs = operands[0]
        rhs = operands[1]

        if op in (LowLevelILOperation.LLIL_AND, LowLevelILOperation.LLIL_OR, LowLevelILOperation.LLIL_XOR):
            # AF is undefined for logical ops on x86; use a stable 0 to avoid
            # polluting MLIL/HLIL with "unimplemented" pseudo-ops.
            return il.const(1, 0)

        if op == LowLevelILOperation.LLIL_ADD:
            result = il.add(w, lhs, rhs)
        elif op == LowLevelILOperation.LLIL_SUB:
            result = il.sub(w, lhs, rhs)
        elif op == LowLevelILOperation.LLIL_ADC and len(operands) >= 3:
            result = il.add_carry(w, lhs, rhs, operands[2])
        elif op == LowLevelILOperation.LLIL_SBB and len(operands) >= 3:
            result = il.sub_borrow(w, lhs, rhs, operands[2])
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
        if flag == "p":
            parity = self._calc_parity_flag_expr(op, size, operands, il)
            if parity is not None:
                return parity
        if flag == "a":
            aux = self._calc_aux_carry_flag_expr(op, size, operands, il)
            if aux is not None:
                return aux
        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

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

Intel8086.register()
