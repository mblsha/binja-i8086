from binaryninja.lowlevelil import LLIL_TEMP, LowLevelILLabel

from ..helpers import *
from . import *


__all__ = ['Daa', 'Das', 'Aaa', 'Aas', 'Aam', 'Aad']


class Adjust(Instruction):
    def _undef_flags(self, il, names):
        for name in names:
            il.append(il.set_flag(name, il.undefined()))

    def _write_szp_from_al(self, il):
        # A zero-valued logical identity gives BN the final AL value from which
        # to derive SF/ZF/PF without altering it.
        value = il.or_expr(1, il.reg(1, 'al'), il.const(1, 0), 'psz')
        il.append(il.set_reg(1, 'al', value))


class DecimalAdjust(Adjust):
    subtract = False

    def name(self):
        return 'das' if self.subtract else 'daa'

    def lift(self, il, addr):
        old_al = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(1, old_al, il.reg(1, 'al')))
        # Append before deriving the next temporary id.  Merely reading
        # ``temp_reg_count`` does not reserve a register in Binary Ninja.
        old_cf = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(1, old_cf, il.flag('c')))

        low_adjust = LowLevelILLabel()
        low_done = LowLevelILLabel()
        low_nibble = il.and_expr(1, il.reg(1, old_al), il.const(1, 0x0f))
        low_gt_nine = il.compare_unsigned_greater_than(1, low_nibble, il.const(1, 9))
        low_cond = il.or_expr(1, low_gt_nine, il.flag('a'))
        il.append(il.if_expr(low_cond, low_adjust, low_done))
        il.mark_label(low_adjust)
        if self.subtract:
            il.append(il.set_reg(1, 'al', il.sub(1, il.reg(1, 'al'), il.const(1, 6))))
        else:
            il.append(il.set_reg(1, 'al', il.add(1, il.reg(1, 'al'), il.const(1, 6))))
        il.append(il.set_flag('a', il.const(1, 1)))
        after_low = LowLevelILLabel()
        il.append(il.goto(after_low))
        il.mark_label(low_done)
        il.append(il.set_flag('a', il.const(1, 0)))
        il.mark_label(after_low)

        high_adjust = LowLevelILLabel()
        high_done = LowLevelILLabel()
        old_gt_99 = il.compare_unsigned_greater_than(1, il.reg(1, old_al), il.const(1, 0x99))
        high_cond = il.or_expr(1, old_gt_99, il.reg(1, old_cf))
        il.append(il.if_expr(high_cond, high_adjust, high_done))
        il.mark_label(high_adjust)
        if self.subtract:
            il.append(il.set_reg(1, 'al', il.sub(1, il.reg(1, 'al'), il.const(1, 0x60))))
        else:
            il.append(il.set_reg(1, 'al', il.add(1, il.reg(1, 'al'), il.const(1, 0x60))))
        il.append(il.set_flag('c', il.const(1, 1)))
        after_high = LowLevelILLabel()
        il.append(il.goto(after_high))
        il.mark_label(high_done)
        il.append(il.set_flag('c', il.const(1, 0)))
        il.mark_label(after_high)

        self._write_szp_from_al(il)
        self._undef_flags(il, ('o',))


class Daa(DecimalAdjust):
    pass


class Das(DecimalAdjust):
    subtract = True


class AsciiAdjust(Adjust):
    subtract = False

    def name(self):
        return 'aas' if self.subtract else 'aaa'

    def lift(self, il, addr):
        adjust = LowLevelILLabel()
        no_adjust = LowLevelILLabel()
        done = LowLevelILLabel()
        low_nibble = il.and_expr(1, il.reg(1, 'al'), il.const(1, 0x0f))
        low_gt_nine = il.compare_unsigned_greater_than(1, low_nibble, il.const(1, 9))
        cond = il.or_expr(1, low_gt_nine, il.flag('a'))
        il.append(il.if_expr(cond, adjust, no_adjust))
        il.mark_label(adjust)
        if self.subtract:
            il.append(il.set_reg(2, 'ax', il.sub(2, il.reg(2, 'ax'), il.const(2, 0x106))))
        else:
            il.append(il.set_reg(2, 'ax', il.add(2, il.reg(2, 'ax'), il.const(2, 0x106))))
        il.append(il.set_flag('a', il.const(1, 1)))
        il.append(il.set_flag('c', il.const(1, 1)))
        il.append(il.goto(done))
        il.mark_label(no_adjust)
        il.append(il.set_flag('a', il.const(1, 0)))
        il.append(il.set_flag('c', il.const(1, 0)))
        il.mark_label(done)
        il.append(il.set_reg(1, 'al', il.and_expr(1, il.reg(1, 'al'), il.const(1, 0x0f))))
        self._undef_flags(il, ('p', 'z', 's', 'o'))


class Aaa(AsciiAdjust):
    pass


class Aas(AsciiAdjust):
    subtract = True


class AamAad(InstrHasImm, Adjust):
    def width(self):
        return 1

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        if self.imm != 10:
            tokens += asm(('int', fmt_imm(self.imm), self.imm))
        return tokens


class Aam(AamAad):
    def name(self):
        return 'aam'

    def lift(self, il, addr):
        if self.imm == 0:
            # The immediate byte is the radix used by the original hardware;
            # a zero radix raises the same type-0 divide interrupt as DIV.
            self._lift_interrupt(il, addr, self.length(), 0)
            return
        value = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(1, value, il.reg(1, 'al')))
        il.append(il.set_reg(1, 'ah', il.div_unsigned(1, il.reg(1, value), il.const(1, self.imm))))
        result = il.mod_unsigned(1, il.reg(1, value), il.const(1, self.imm), flags='psz')
        il.append(il.set_reg(1, 'al', result))
        self._undef_flags(il, ('c', 'a', 'o'))


class Aad(AamAad):
    def name(self):
        return 'aad'

    def lift(self, il, addr):
        product = il.mult(1, il.reg(1, 'ah'), il.const(1, self.imm))
        result = il.add(1, il.reg(1, 'al'), product, flags='psz')
        il.append(il.set_reg(1, 'al', result))
        il.append(il.set_reg(1, 'ah', il.const(1, 0)))
        self._undef_flags(il, ('c', 'a', 'o'))
