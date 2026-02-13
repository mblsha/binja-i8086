from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['JmpFarImm', 'JmpFarMem',
           'JmpNearImm', 'JmpNearRM',
           'JmpShort', 'JmpCond',
           'Loop', 'Loope', 'Loopne', 'Jcxz']


class Jmp(Instruction):
    def name(self):
        return 'jmp'


class JmpFarImm(Jmp):
    def length(self):
        return 5

    def decode(self, decoder, addr):
        Jmp.decode(self, decoder, addr)
        self.ip = decoder.unsigned_word()
        self.cs = decoder.unsigned_word()

    def encode(self, encoder, addr):
        Jmp.encode(self, encoder, addr)
        encoder.unsigned_word(self.ip)
        encoder.unsigned_word(self.cs)

    def target(self):
        return (self.cs << 4) + self.ip

    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.UnconditionalBranch, self.target())

    def render(self, addr):
        tokens = Jmp.render(self, addr)
        tokens += asm(
            ('addr', fmt_code_abs(self.cs), self.cs << 4),
            ('opsep', ':'),
            ('addr', fmt_code_abs(self.ip), self.target()),
        )
        return tokens

    def lift(self, il, addr):
        il.append(il.set_reg(2, 'cs', il.const(2, self.cs)))
        il.append(il.jump(il.const(3, self.target())))


class JmpFarMem(InstrHasModRegRM, Instr16Bit, Jmp):
    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.IndirectBranch)

    def render(self, addr):
        if self._mod_bits() == 0b11:
            return asm(('instr', '(unassigned)'))

        tokens = Jmp.render(self, addr)
        tokens += asm(
            ('text', 'far'),
            ('opsep', ' '),
        )
        tokens += self._render_reg_mem(fixed_width=True)
        return tokens

    def lift(self, il, addr):
        if self._mod_bits() == 0b11:
            il.append(il.undefined())
            return

        cs, ip = self._lift_load_far(il, self._lift_reg_mem(il))
        il.append(il.set_reg(2, 'cs', cs))
        il.append(il.jump(self._lift_phys_addr(il, cs, ip)))


class JmpNearImm(Jmp):
    def length(self):
        return 3

    def decode(self, decoder, addr):
        Jmp.decode(self, decoder, addr)
        self.ip = addr + self.length() + decoder.signed_word()

    def encode(self, encoder, addr):
        Jmp.encode(self, encoder, addr)
        encoder.signed_word(self.ip - addr - self.length())

    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.UnconditionalBranch, self.ip)

    def render(self, addr):
        tokens = Jmp.render(self, addr)
        tokens += asm(
            ('codeRelAddr', fmt_code_rel(self.ip - addr), self.ip),
        )
        return tokens

    def lift(self, il, addr):
        label = il.get_label_for_address(il.arch, self.ip)
        if label is None:
            il.append(il.jump(il.const(3, self.ip)))
        else:
            il.append(il.goto(label))


class JmpNearRM(InstrHasModRegRM, Instr16Bit, Jmp):
    def _default_segment(self):
        return 'cs'

    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.IndirectBranch)

    def render(self, addr):
        tokens = Jmp.render(self, addr)
        tokens += self._render_reg_mem()
        return tokens

    def _try_resolve_cs_jump_table_target(self, il, addr):
        if self._mod_bits() == 0b11:
            return None
        if not (self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110):
            return None
        if self.segment() != "cs":
            return None

        view = self._view_from_il(il)
        if view is None:
            return None

        segment_base = self._segment_base_for_addr(view, addr)
        slot_addr = (segment_base + (self.disp & 0xffff)) & 0xfffff
        target_off = self._read_u16(view, slot_addr)
        if target_off is None:
            return None
        if target_off == 0:
            return None
        return (segment_base + target_off) & 0xfffff

    def _try_lift_cs_indirect_target(self, il, addr):
        """Lift cs:[..] near-indirect jumps with a stable page base.

        For runtime flat images, replacing `cs<<4` with the mapped 64K page base
        makes HLIL less noisy (no synthetic entry_cs temp) while preserving the
        segmented addressing semantics.
        """

        if self._mod_bits() == 0b11:
            return None
        if self.segment() != "cs":
            return None

        view = self._view_from_il(il)
        if view is None:
            return None

        segment_base = self._segment_base_for_addr(view, addr)

        def _zext16(expr):
            zero_extend = getattr(il, "zero_extend", None)
            if callable(zero_extend):
                try:
                    return zero_extend(3, expr)
                except Exception:
                    pass
            return il.and_expr(3, il.const(3, 0xFFFF), il.sign_extend(3, expr))

        offset = self._lift_reg_mem(il, only_calc_addr=True)
        slot_phys = il.add(
            3,
            self._const_addr(il, segment_base),
            _zext16(offset),
        )
        slot_phys = il.and_expr(3, il.const(3, 0xFFFFF), slot_phys)

        target_off = il.load(2, slot_phys)
        target_phys = il.add(
            3,
            self._const_addr(il, segment_base),
            _zext16(target_off),
        )
        target_phys = il.and_expr(3, il.const(3, 0xFFFFF), target_phys)
        return target_phys

    def lift(self, il, addr):
        resolved = self._try_resolve_cs_jump_table_target(il, addr)
        if resolved is not None:
            il.append(il.jump(self._const_addr(il, resolved)))
            return
        cs_indirect = self._try_lift_cs_indirect_target(il, addr)
        if cs_indirect is not None:
            il.append(il.jump(cs_indirect))
            return
        il.append(il.jump(self._lift_phys_addr(il, self.segment(), self._lift_reg_mem(il))))


class JmpShort(Jmp):
    def length(self):
        return 2

    def decode(self, decoder, addr):
        Jmp.decode(self, decoder, addr)
        self.ip = addr + self.length() + decoder.signed_byte()

    def encode(self, encoder, addr):
        Jmp.encode(self, encoder, addr)
        encoder.signed_byte(self.ip - addr - self.length())

    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.UnconditionalBranch, self.ip)

    def render(self, addr):
        tokens = Jmp.render(self, addr)
        tokens += asm(
            ('codeRelAddr', fmt_code_rel(self.ip - addr), self.ip),
        )
        return tokens

    def lift(self, il, addr):
        label = il.get_label_for_address(il.arch, self.ip)
        if label is None:
            il.append(il.jump(il.const(3, self.ip)))
        else:
            il.append(il.goto(label))


class JmpCond(JmpShort):
    def name(self):
        return instr_jump[self.opcode & 0b1111]

    def to_always(self):
        branch = JmpShort()
        branch.opcode = 0xeb
        branch.ip     = self.ip
        return branch

    def to_inverted(self):
        branch = JmpCond()
        branch.opcode = self.opcode ^ 0b0001
        branch.ip     = self.ip
        return branch

    def analyze(self, info, addr):
        Jmp.analyze(self, info, addr)
        info.add_branch(BranchType.TrueBranch, self.ip)
        info.add_branch(BranchType.FalseBranch, addr + self.length())

    def lift(self, il, addr):
        untaken_label = il.get_label_for_address(il.arch, addr + self.length())
        if untaken_label is None:
            mark_untaken = True
            untaken_label = LowLevelILLabel()
        else:
            mark_untaken = False
        taken_label   = il.get_label_for_address(il.arch, self.ip)
        if taken_label is None:
            mark_taken = True
            taken_label = LowLevelILLabel()
        else:
            mark_taken = False

        name = self.name()
        if name == 'jpe':
            il.append(il.if_expr(il.flag('p'), taken_label, untaken_label))
        elif name == 'jpo':
            il.append(il.if_expr(il.flag('p'), untaken_label, taken_label))
        else:
            cond = jump_cond[name]
            il.append(il.if_expr(il.flag_condition(cond), taken_label, untaken_label))

        if mark_taken:
            il.mark_label(taken_label)
            il.append(il.jump(il.const(3, self.ip)))
        if mark_untaken:
            il.mark_label(untaken_label)


class Loop(JmpCond):
    def name(self):
        return instr_loop[self.opcode & 0b11]

    def _lift_loop_cond(self, il):
        il.append(il.set_reg(2, 'cx', il.sub(2, il.reg(2, 'cx'), il.const(2, 1))))
        cond = il.compare_not_equal(2, il.reg(2, 'cx'), il.const(2, 0))
        if hasattr(self, '_lift_loop_pred'):
            cond = il.and_expr(1, cond, self._lift_loop_pred(il))
        return cond

    def lift(self, il, addr):
        untaken_label = il.get_label_for_address(il.arch, addr + self.length())
        if untaken_label is None:
            mark_untaken = True
            untaken_label = LowLevelILLabel()
        else:
            mark_untaken = False
        taken_label   = il.get_label_for_address(il.arch, self.ip)
        if taken_label is None:
            mark_taken = True
            taken_label = LowLevelILLabel()
        else:
            mark_taken = False

        il.append(il.if_expr(self._lift_loop_cond(il), taken_label, untaken_label))
        if mark_taken:
            il.mark_label(taken_label)
            il.append(il.jump(il.const(3, self.ip)))
        if mark_untaken:
            il.mark_label(untaken_label)


class Loope(Loop):
    def _lift_loop_pred(self, il):
        return il.flag('z')


class Loopne(Loop):
    def _lift_loop_pred(self, il):
        return il.not_expr(1, il.flag('z'))


class Jcxz(Loop):
    def _lift_loop_cond(self, il):
        return il.compare_equal(2, il.reg(2, 'cx'), il.const(2, 0))
