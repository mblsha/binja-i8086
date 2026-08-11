from binaryninja.lowlevelil import LowLevelILLabel

from ..helpers import *
from ..tables import *
from . import *
from .str import InstrString


__all__ = ['Repe', 'Repne']


class Rep(Prefix):
    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += self.next.render(self._near_target(addr, self.length(), 0))
        return tokens

    def _last_repeat_prefix(self):
        last = self
        instr = self.next
        while isinstance(instr, Prefix):
            if isinstance(instr, Rep):
                last = instr
            instr = instr.next
        return last

    def _zf_check(self):
        instr = self.terminal_instruction()
        if not isinstance(instr, InstrString):
            return None

        if instr.base_name in ('movs', 'lods', 'stos'):
            return False
        elif instr.base_name in ('cmps', 'scas'):
            return True

    def lift(self, il, addr):
        # Prefix state is overwritten as additional prefixes are decoded.  If
        # both F2 and F3 occur, only the last repeat prefix controls ZF.
        if self._last_repeat_prefix() is not self:
            self.next.lift(il, self._near_target(addr, self.length(), 0))
            return

        instr, instr_addr = self.terminal_addr(addr)
        if not isinstance(instr, InstrString):
            il.append(il.undefined())
            return

        # Use a known DF value when the surrounding LLIL context exposes one;
        # otherwise the string instruction emits an explicit direction branch.
        preheader_instr = il.append(il.nop())
        try:
            df_values = il[preheader_instr].get_possible_flag_values('d')
        except Exception:
            df_values = None

        header_label = LowLevelILLabel()
        exit_label = LowLevelILLabel()

        # REP executes zero times when CX starts at zero.
        nonzero = il.compare_not_equal(2, il.reg(2, 'cx'), il.const(2, 0))
        il.append(il.if_expr(nonzero, header_label, exit_label))
        il.mark_label(header_label)
        instr.lift(il, instr_addr, df_values)

        il.append(il.set_reg(2, 'cx', il.sub(2, il.reg(2, 'cx'), il.const(2, 1))))
        cond = il.compare_not_equal(2, il.reg(2, 'cx'), il.const(2, 0))
        if self._zf_check():
            zf_cond = il.compare_equal(1, il.flag('z'), il.const(1, self._zf_cond))
            cond = il.and_expr(1, cond, zf_cond)
        il.append(il.if_expr(cond, header_label, exit_label))
        il.mark_label(exit_label)


class Repe(Rep):
    _zf_cond = 1

    def name(self):
        if self._zf_check():
            return 'repe'
        else:
            return 'rep'


class Repne(Rep):
    _zf_cond = 0

    def name(self):
        return 'repne'
