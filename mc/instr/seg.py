from ..helpers import *
from ..tables import *
from . import *


__all__ = ['Segment']


class Segment(Prefix):
    def reg_seg(self):
        return reg_seg[(self.opcode & 0b11000) >> 3]

    def decode(self, decoder, addr):
        Prefix.decode(self, decoder, addr)
        terminal = self.terminal_instruction()
        # Prefixes are decoded from left to right. The innermost (last) segment
        # override wins when multiple overrides are present.
        if hasattr(terminal, 'segment_override') and terminal.segment_override is None:
            terminal.segment_override = self.reg_seg()

    def render(self, addr):
        if hasattr(self.terminal_instruction(), 'segment_override'):
            tokens = []
        else:
            tokens = asm(
                ('reg', self.reg_seg()),
                ('opsep', ' ')
            )
        tokens += self.next.render(self._near_target(addr, self.length(), 0))
        return tokens
