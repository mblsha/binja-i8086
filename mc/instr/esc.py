from ..helpers import *
from . import *


__all__ = ['Esc']


class Esc(InstrHasModRegRM, Instr16Bit, Instruction):
    """Opaque 8087 escape operation with correct decoding and address effects."""

    def name(self):
        return 'esc'

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        operation = ((self.opcode & 0x7) << 3) | self._reg_bits()
        tokens += asm(('int', fmt_hex(operation), operation), ('opsep', ', '))
        tokens += self._render_reg_mem(fixed_width=True)
        return tokens

    def lift(self, il, addr):
        operation = ((self.opcode & 0x7) << 3) | self._reg_bits()
        if self._mod_bits() == 0b11:
            operand = il.const(3, 0x100 | self._reg_mem_bits())
        else:
            operand = self._lift_reg_mem_addr(il)
        il.append(il.intrinsic([], 'esc', [il.const(2, operation), operand]))
