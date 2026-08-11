from ..helpers import *
from ..tables import *
from . import *


__all__ = ['Lea']


class Lea(InstrHasModRegRM, Instr16Bit, Instruction):
    def name(self):
        return 'lea'

    def dst_reg(self):
        return self._reg()

    def render(self, addr):
        if self._mod_bits() == 0b11:
            return asm(('instr', '(unassigned)'))
        tokens = Instruction.render(self, addr)
        tokens += asm(
            ('reg', self.dst_reg()),
            ('opsep', ', '),
        )
        tokens += self._render_reg_mem(fixed_width=True)
        return tokens

    def lift(self, il, addr):
        if self._mod_bits() == 0b11:
            il.append(il.undefined())
            return
        il.append(il.set_reg(2, self.dst_reg(), self._lift_reg_mem(il, only_calc_addr=True)))
