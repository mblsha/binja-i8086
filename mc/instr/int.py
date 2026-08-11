from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LowLevelILLabel

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['IntImm', 'Int3', 'Into']


class Int(Instruction):
    def analyze(self, info, addr):
        Instruction.analyze(self, info, addr)
        info.add_branch(BranchType.SystemCall)

    def lift(self, il, addr):
        self._lift_interrupt(il, addr, self.length(), self.number)


class IntImm(Int):
    def name(self):
        return 'int'

    def length(self):
        return 2

    def decode(self, decoder, addr):
        Int.decode(self, decoder, addr)
        self.number = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        Int.encode(self, encoder, addr)
        encoder.unsigned_byte(self.number)

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += asm(
            ('int', fmt_hex(self.number), self.number)
        )
        return tokens


class Int3(Int):
    number = 3

    def name(self):
        return 'int3'


class Into(Int):
    number = 4

    def name(self):
        return 'into'

    def lift(self, il, addr):
        overflow_label = LowLevelILLabel()
        normal_label   = LowLevelILLabel()
        il.append(il.if_expr(il.flag('o'), overflow_label, normal_label))
        il.mark_label(overflow_label)
        Int.lift(self, il, addr)
        il.mark_label(normal_label)
