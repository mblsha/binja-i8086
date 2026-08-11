from binaryninja.lowlevelil import LLIL_TEMP, LowLevelILLabel

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['AluLogicRegRM',  'AluLogicRMReg',
           'AluLogicAccImm', 'AluLogicRMImm',
           'AluShiftRM',
           'AluArithRegMem']


class AluLogic(InstrHasWidth, Instruction):
    def name(self):
        return instr_alu_logic[(self.opcode & 0b111000) >> 3]

    def _is_logic_op(self):
        return self.name() in ('or', 'and', 'xor')

    def _logic_flag_write(self):
        return 'logic' if self._is_logic_op() else '*'

    def _append_logic_flag_fixups(self, il):
        if not self._is_logic_op():
            return
        # x86 logical ops clear carry/overflow deterministically.
        il.append(il.set_flag('c', il.const(1, 0)))
        il.append(il.set_flag('o', il.const(1, 0)))
        il.append(il.set_flag('a', il.undefined()))

    def _op(self, il, lhs, rhs):
        if self.name() == 'add':
            result = il.add(self.width(), lhs, rhs, '*')
        elif self.name() == 'or':
            result = il.or_expr(self.width(), lhs, rhs, self._logic_flag_write())
        elif self.name() == 'adc':
            result = il.add_carry(self.width(), lhs, rhs, il.flag('c'), '*')
        elif self.name() == 'sbb':
            result = il.sub_borrow(self.width(), lhs, rhs, il.flag('c'), '*')
        elif self.name() == 'and':
            result = il.and_expr(self.width(), lhs, rhs, self._logic_flag_write())
        elif self.name() == 'sub':
            result = il.sub(self.width(), lhs, rhs, '*')
        elif self.name() == 'xor':
            result = il.xor_expr(self.width(), lhs, rhs, self._logic_flag_write())
        elif self.name() == 'cmp':
            il.append(il.sub(self.width(), lhs, rhs, '*'))
            return
        return result


class AluLogicRMReg(InstrHasModRegRM, AluLogic):
    def src_reg(self):
        return self._reg()

    def render(self, addr):
        tokens = AluLogic.render(self, addr)
        tokens += self._render_reg_mem()
        tokens += asm(
            ('opsep', ', '),
            ('reg', self.src_reg()),
        )
        return tokens

    def lift(self, il, addr):
        w = self.width()
        result = self._op(il, self._lift_reg_mem(il), il.reg(w, self.src_reg()))
        if result is not None:
            self._lift_set_reg_mem(il, result)
            self._append_logic_flag_fixups(il)


class AluLogicRegRM(InstrHasModRegRM, AluLogic):
    def dst_reg(self):
        return self._reg()

    def render(self, addr):
        tokens = AluLogic.render(self, addr)
        tokens += asm(
            ('reg', self.dst_reg()),
            ('opsep', ', '),
        )
        tokens += self._render_reg_mem()
        return tokens

    def lift(self, il, addr):
        w = self.width()
        result = self._op(il, il.reg(w, self.dst_reg()), self._lift_reg_mem(il))
        if result is not None:
            il.append(il.set_reg(w, self.dst_reg(), result))
            self._append_logic_flag_fixups(il)


class AluLogicAccImm(InstrHasImm, AluLogic):
    def dst_reg(self):
        return 'ax' if self.width() == 2 else 'al'

    def render(self, addr):
        tokens = AluLogic.render(self, addr)
        tokens += asm(
            ('reg', self.dst_reg()),
            ('opsep', ', '),
            ('int', fmt_imm(self.imm), self.imm),
        )
        return tokens

    def lift(self, il, addr):
        w = self.width()
        result = self._op(il, il.reg(w, self.dst_reg()), il.const(w, self.imm))
        if result is not None:
            il.append(il.set_reg(w, self.dst_reg(), result))
            self._append_logic_flag_fixups(il)


class AluLogicRMImm(InstrHasModRegRM, AluLogic):
    def name(self):
        return instr_alu_logic[self._reg_bits()]

    def _sign_extend(self):
        return (self.opcode & 0b10) >> 1

    def _imm_width(self):
        if self.width() == 2 and not self._sign_extend():
            return 2
        else:
            return 1

    def length(self):
        return InstrHasModRegRM.length(self) + self._imm_width()

    def decode(self, decoder, addr):
        InstrHasModRegRM.decode(self, decoder, addr)
        self.imm = decoder.immediate(self._imm_width())

    def encode(self, encoder, addr):
        InstrHasModRegRM.encode(self, encoder, addr)
        encoder.immediate(self.imm, self._imm_width())

    def render(self, addr):
        tokens = AluLogic.render(self, addr)
        tokens += self._render_reg_mem()
        if self._sign_extend():
            tokens += asm(
                ('opsep', ', '),
                ('text', op_width[self.opcode & 0b1]),
                ('opsep', ' '),
                ('int', fmt_imm_sign(self.imm), self.imm),
            )
        else:
            tokens += asm(
                ('opsep', ', '),
                ('int', fmt_imm(self.imm), self.imm),
            )
        return tokens

    def lift(self, il, addr):
        w = self.width()
        lhs = self._lift_reg_mem(il)
        rhs = il.const(self._imm_width(), self.imm)
        if self._sign_extend():
            rhs = il.sign_extend(w, rhs)
        result = self._op(il, lhs, rhs)
        if result is not None:
            self._lift_set_reg_mem(il, result)
            self._append_logic_flag_fixups(il)


class AluShiftRM(InstrHasModRegRM, InstrHasWidth, Instruction):
    def name(self):
        return instr_alu_shift[self._reg_bits()]

    def dst_reg(self):
        return self._reg2()

    def src_reg(self):
        if self.opcode & 0b10:
            return 'cl'
        else:
            return None

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += self._render_reg_mem()
        tokens += asm(('opsep', ', '))
        if self.src_reg():
            tokens += asm(('reg', self.src_reg()))
        else:
            tokens += asm(('int', '1', 1))
        return tokens

    def lift(self, il, addr):
        w = self.width()
        lhs = self._lift_reg_mem(il)
        rhs = il.reg(1, self.src_reg()) if self.src_reg() else il.const(1, 1)
        name = self.name()
        if name not in ('rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sar'):
            il.append(il.undefined())
            return

        done = None
        if self.src_reg():
            # A zero count performs no operation and preserves every flag.
            # Keep the flag-writing shift/rotate expression off that path.
            execute = LowLevelILLabel()
            done = LowLevelILLabel()
            nonzero = il.compare_not_equal(1, rhs, il.const(1, 0))
            il.append(il.if_expr(nonzero, execute, done))
            il.mark_label(execute)

        if name == 'rol':
            result = il.rotate_left(w, lhs, rhs, 'co')
        elif name == 'ror':
            result = il.rotate_right(w, lhs, rhs, 'co')
        elif name == 'rcl':
            result = il.rotate_left_carry(w, lhs, rhs, il.flag('c'), 'co')
        elif name == 'rcr':
            result = il.rotate_right_carry(w, lhs, rhs, il.flag('c'), 'co')
        elif name == 'shl':
            result = il.shift_left(w, lhs, rhs, 'shift')
        elif name == 'shr':
            result = il.logical_shift_right(w, lhs, rhs, 'shift')
        elif name == 'sar':
            result = il.arith_shift_right(w, lhs, rhs, 'shift')
        self._lift_set_reg_mem(il, result)
        if name in ('shl', 'shr', 'sar'):
            il.append(il.set_flag('a', il.undefined()))

        if done is None:
            return

        # OF is defined only for a count of one.  Count zero already bypasses
        # the operation above, so every remaining non-one count is multibit.
        one = LowLevelILLabel()
        multibit = LowLevelILLabel()
        il.append(il.if_expr(il.compare_equal(1, rhs, il.const(1, 1)), one, multibit))
        il.mark_label(multibit)
        il.append(il.set_flag('o', il.undefined()))
        il.append(il.goto(done))
        il.mark_label(one)
        il.mark_label(done)


class AluArithRegMem(InstrHasModRegRM, InstrHasWidth, Instruction):
    def name(self):
        return instr_alu_arith[self._reg_bits()]

    def render(self, addr):
        tokens = Instruction.render(self, addr)
        tokens += self._render_reg_mem()
        return tokens

    def lift(self, il, addr):
        w = self.width()
        name = self.name()
        if name == 'not':
            self._lift_set_reg_mem(il, il.not_expr(w, self._lift_reg_mem(il)))
        elif name == 'neg':
            self._lift_set_reg_mem(il, il.neg_expr(w, self._lift_reg_mem(il), flags='*'))
        elif name in ('mul', 'imul'):
            accum  = il.reg(w, 'ax') if w == 2 else il.reg(w, 'al')
            if name == 'imul':
                result = il.mult_double_prec_signed(w, accum, self._lift_reg_mem(il), flags='co')
            else:
                result = il.mult_double_prec_unsigned(w, accum, self._lift_reg_mem(il), flags='co')
            if w == 2:
                il.append(il.set_reg_split(w, 'dx', 'ax', result))
            else:
                il.append(il.set_reg(2, 'ax', result))
            for flag in ('p', 'a', 'z', 's'):
                il.append(il.set_flag(flag, il.undefined()))
        elif name in ('div', 'idiv'):
            dividend = il.reg_split(w, 'dx', 'ax') if w == 2 else il.reg(w * 2, 'ax')
            divisor = LLIL_TEMP(il.temp_reg_count)
            il.append(il.set_reg(w, divisor, self._lift_reg_mem(il)))
            if name == 'div':
                quotient_expr = il.div_double_prec_unsigned(w, dividend, il.reg(w, divisor))
                remainder_expr = il.mod_double_prec_unsigned(w, dividend, il.reg(w, divisor))
            else:
                quotient_expr = il.div_double_prec_signed(w, dividend, il.reg(w, divisor))
                remainder_expr = il.mod_double_prec_signed(w, dividend, il.reg(w, divisor))
            quotient = LLIL_TEMP(il.temp_reg_count)
            il.append(il.set_reg(w, quotient, quotient_expr))
            # ``temp_reg_count`` is the number of temporaries already present
            # in the function, not an allocator.  Append the quotient write
            # before asking for the remainder temporary so the two results do
            # not alias in real Binary Ninja LLIL.
            remainder = LLIL_TEMP(il.temp_reg_count)
            il.append(il.set_reg(w, remainder, remainder_expr))
            if w == 2:
                il.append(il.set_reg(w, 'ax', il.reg(w, quotient)))
                il.append(il.set_reg(w, 'dx', il.reg(w, remainder)))
            else:
                il.append(il.set_reg(w, 'al', il.reg(w, quotient)))
                il.append(il.set_reg(w, 'ah', il.reg(w, remainder)))
            for flag in ('c', 'p', 'a', 'z', 's', 'o'):
                il.append(il.set_flag(flag, il.undefined()))
        else:
            il.append(il.undefined())
