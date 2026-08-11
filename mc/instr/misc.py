from ..helpers import *
from ..tables import *
from . import *


__all__ = ['Hlt', 'Wait', 'Lock', 'Salc']


class Hlt(Instruction):
    def name(self):
        return 'hlt'

    def lift(self, il, addr):
        # HLT resumes at the following instruction after a maskable interrupt.
        il.append(il.intrinsic([], 'hlt', []))


class Wait(Instruction):
    def name(self):
        return 'wait'

    def lift(self, il, addr):
        il.append(il.intrinsic([], 'wait', []))


class Salc(Instruction):
    def name(self):
        return 'salc'

    def lift(self, il, addr):
        # AL becomes 00 or FF according to CF; flags are unaffected.
        value = il.sub(1, il.const(1, 0), il.flag('c'))
        il.append(il.set_reg(1, 'al', value))


class Lock(Prefix):
    def name(self):
        return 'lock'

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += self.next.render(self._near_target(addr, self.length(), 0))
        return tokens

    def lift(self, il, addr):
        # 8086 LOCK is a prefix that modifies bus semantics for the following
        # instruction; BN LLIL has no explicit lock primitive, so we lift the
        # wrapped instruction directly.
        self.next.lift(il, self._near_target(addr, self.length(), 0))
