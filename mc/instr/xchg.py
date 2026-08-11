from binaryninja.lowlevelil import LLIL_TEMP

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['Nop', 'XchgRegReg', 'XchgRegRM']


class Nop(Instruction):
    def name(self):
        return 'nop'

    def lift(self, il, addr):
        il.append(il.nop())


class Xchg(Instruction):
    def name(self):
        return 'xchg'


class XchgRegReg(Xchg):
    def regL(self):
        return 'ax'

    def regR(self):
        return reg16[self.opcode & 0b111]

    def render(self, addr):
        tokens = Xchg.render(self, addr)
        tokens += asm(
            ('reg', self.regL()),
            ('opsep', ', '),
            ('reg', self.regR()),
        )
        return tokens

    def lift(self, il, addr):
        temp = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, temp, il.reg(2, self.regL())))
        il.append(il.set_reg(2, self.regL(), il.reg(2, self.regR())))
        il.append(il.set_reg(2, self.regR(), il.reg(2, temp)))


class XchgRegRM(InstrHasModRegRM, InstrHasWidth, Xchg):
    def regL(self):
        return self._reg()

    def render(self, addr):
        tokens = Xchg.render(self, addr)
        tokens += asm(
            ('reg', self.regL()),
            ('opsep', ', '),
        )
        tokens += self._render_reg_mem()
        return tokens

    def lift(self, il, addr):
        w = self.width()
        if self._mod_bits() == 0b11:
            temp = LLIL_TEMP(il.temp_reg_count)
            il.append(il.set_reg(w, temp, il.reg(w, self.regL())))
            il.append(il.set_reg(w, self.regL(), self._lift_reg_mem(il)))
            self._lift_set_reg_mem(il, il.reg(w, temp))
            return

        # Cache both the address and loaded value before changing a register
        # that may participate in the effective address (e.g. xchg bx,[bx]).
        ea = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(3, ea, self._lift_reg_mem_addr(il)))
        temp = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(w, temp, il.reg(w, self.regL())))
        value = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(w, value, self._lift_mem_load(il, w, il.reg(3, ea))))
        il.append(il.set_reg(w, self.regL(), il.reg(w, value)))
        self._lift_mem_store(il, w, il.reg(3, ea), il.reg(w, temp))
