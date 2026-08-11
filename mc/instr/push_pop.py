from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LLIL_TEMP

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['PushReg', 'PopReg',
           'PushSeg', 'PopSeg', 'PopCS',
           'PushRM',  'PopRM',
           'PushF',   'PopF']


class PushPopReg(Instruction):
    def reg(self):
        return reg16[self.opcode & 0b111]

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += asm(
            ('reg', self.reg())
        )
        return tokens


class PushReg(PushPopReg):
    def name(self):
        return 'push'

    def lift(self, il, addr):
        value = il.reg(2, self.reg())
        if self.reg() == 'sp':
            # On the original 8086, SP is decremented before the source value
            # is read, so PUSH SP stores the new SP (unlike later x86 CPUs).
            value = il.sub(2, value, il.const(2, 2))
        il.append(il.push(2, value))


class PopReg(PushPopReg):
    def name(self):
        return 'pop'

    def lift(self, il, addr):
        il.append(il.set_reg(2, self.reg(), il.pop(2)))


class PushPopSeg(object):
    def reg(self):
        return reg_seg[(self.opcode & 0b111000) >> 3]


class PushSeg(PushPopSeg, PushReg):
    pass


class PopSeg(PushPopSeg, PopReg):
    pass


class PopCS(PopSeg):
    """The original 8086 opcode 0F (removed on later x86 processors)."""

    def reg(self):
        return 'cs'

    def analyze(self, info, addr):
        Instruction.analyze(self, info, addr)
        info.add_branch(BranchType.IndirectBranch)

    def lift(self, il, addr):
        new_cs = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, new_cs, il.pop(2)))
        il.append(il.set_reg(2, 'cs', il.reg(2, new_cs)))
        next_ip = (addr + self.length()) & 0xffff
        il.append(il.jump(self._lift_phys_addr(il, il.reg(2, new_cs), il.const(2, next_ip))))


class PushRM(InstrHasModRegRM, Instr16Bit, Instruction):
    def name(self):
        return 'push'

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += self._render_reg_mem()
        return tokens

    def lift(self, il, addr):
        value = self._lift_reg_mem(il)
        if self._mod_bits() == 0b11 and self._reg2() == 'sp':
            value = il.sub(2, value, il.const(2, 2))
        il.append(il.push(2, value))


class PopRM(InstrHasModRegRM, Instr16Bit, Instruction):
    def name(self):
        return 'pop'

    def render(self, addr):
        if self._reg_bits() != 0b000:
            return asm(('instr', '(unassigned)'))

        tokens = Instruction.render(self, addr)
        tokens += self._render_reg_mem()
        return tokens

    def lift(self, il, addr):
        if self._reg_bits() != 0b000:
            il.append(il.undefined())
            return

        value = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, value, il.pop(2)))
        self._lift_set_reg_mem(il, il.reg(2, value))


class PushF(Instruction):
    def name(self):
        return 'pushf'

    def lift(self, il, addr):
        il.append(il.push(2, self._lift_flags_word(il)))


class PopF(Instruction):
    def name(self):
        return 'popf'

    def lift(self, il, addr):
        flags = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, flags, il.pop(2)))
        for flag, flag_bit in flags_bits:
            bit = il.test_bit(2, il.reg(2, flags), il.const(2, flag_bit))
            il.append(il.set_flag(flag, bit))
