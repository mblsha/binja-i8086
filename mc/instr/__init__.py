import builtins
from functools import reduce
from binaryninja.lowlevelil import LLIL_TEMP

from ..helpers import *
from ..tables import *


__all__ = ['Instruction', 'Prefix',
           'InstrHasWidth', 'Instr16Bit',
           'InstrHasImm',
           'InstrHasSegment', 'InstrHasDisp', 'InstrHasModRegRM']


a20_gate = True


class Instruction(object):
    opcodes = {}
    _default_ret_status_flags = ("c", "p", "a", "z", "s", "o")
    _default_ret_flag_shadow_regs = {
        "c": "rc",
        "p": "rp",
        "a": "ra",
        "z": "rz",
        "s": "rs",
        "o": "ro",
    }
    _ret_pass_flag_arch_names = {"8086", "x86_16"}
    _cs_table_lift_disabled_suffixes = ("-vanilla",)

    def __new__(cls, decoder=None):
        if decoder is None:
            return object.__new__(cls)
        else:
            cls = cls.opcodes[decoder.peek(0)]
            if isinstance(cls, dict):
                cls = cls[(decoder.peek(1) & 0b111000) >> 3]
            return object.__new__(cls)

    def name(self):
        return 'unimplemented'

    def length(self):
        return 1

    def total_length(self):
        return self.length()

    def decode(self, decoder, addr):
        self.opcode = decoder.unsigned_byte()

    def encode(self, encoder, addr):
        encoder = encoder.unsigned_byte(self.opcode)

    def analyze(self, info, addr):
        info.length += self.length()

    def render(self, addr):
        return asm(
            ('instr', self.name()),
            ('opsep', ' ' * (8 - len(self.name())))
        )

    def lift(self, il, addr):
        il.append(il.unimplemented())

    def _lift_phys_addr(self, il, seg, disp):
        if isinstance(seg, builtins.str) and seg in il.arch.regs:
            seg = il.reg(2, seg)
        if isinstance(disp, builtins.str) and disp in il.arch.regs:
            disp = il.reg(2, disp)
        # Address arithmetic is 20-bit; explicitly widen the architectural
        # 16-bit segment/offset values before using 3-byte LLIL operations.
        seg = il.zero_extend(3, seg)
        disp = il.zero_extend(3, disp)
        base = il.shift_left(3, seg, il.const(1, 4))
        phys = il.add(3, base, disp)
        if a20_gate:
            phys = il.and_expr(3, il.const(3, 0xfffff), phys)
        return phys

    @staticmethod
    def _near_target(addr, instr_len, displacement):
        """Return a flat address while preserving 8086 IP wrap semantics."""
        segment_page = builtins.int(addr) & ~0xffff
        ip = (builtins.int(addr) + builtins.int(instr_len) + builtins.int(displacement)) & 0xffff
        return segment_page | ip

    @staticmethod
    def _near_displacement(addr, instr_len, target):
        base_ip = (builtins.int(addr) + builtins.int(instr_len)) & 0xffff
        delta = (builtins.int(target) - base_ip) & 0xffff
        return delta - 0x10000 if delta & 0x8000 else delta

    def _view_from_il(self, il):
        try:
            view = getattr(il, "view", None)
            if view is not None:
                return view
        except Exception:
            pass

        try:
            source_function = getattr(il, "source_function", None)
            if source_function is not None:
                view = getattr(source_function, "view", None)
                if view is not None:
                    return view
        except Exception:
            pass

        return None

    def _segment_base_for_addr(self, view, addr):
        addr = builtins.int(addr)
        page_base = addr & ~0xffff

        try:
            containing = [s for s in view.segments if s.start <= addr < s.end]
            if containing:
                # For segmented x86 tables (e.g. cs:[0x3004]) prefer the 64K page base
                # whenever that page is actually mapped, even if analysis added a
                # narrower overlapping overlay segment.
                if any(s.start <= page_base < s.end for s in containing):
                    return page_base

                # Otherwise keep the old overlap preference: most specific region,
                # ties go to the highest base.
                containing.sort(
                    key=lambda s: (
                        builtins.int(s.end) - builtins.int(s.start),
                        -builtins.int(s.start),
                    )
                )
                return builtins.int(containing[0].start)
        except Exception:
            pass

        try:
            segment = view.get_segment_at(addr)
            if segment is not None and segment.start <= addr < segment.end:
                return builtins.int(segment.start)
        except Exception:
            pass

        return page_base

    def _read_u16(self, view, addr):
        try:
            addr = builtins.int(addr)
            low = view.read(addr & 0xfffff, 1)
            high = view.read((addr + 1) & 0xfffff, 1)
            if low is None or high is None:
                return None
            low = bytes(low)
            high = bytes(high)
            if len(low) < 1 or len(high) < 1:
                return None
            return low[0] | (high[0] << 8)
        except Exception:
            return None

    def _const_addr(self, il, addr):
        try:
            return il.const_pointer(3, addr)
        except Exception:
            return il.const(3, addr)

    def _cs_table_lift_enabled(self, il):
        try:
            explicit = getattr(il.arch, "__dict__", {}).get("cs_table_lift", None)
            if explicit is not None:
                return bool(explicit)
        except Exception:
            pass

        try:
            value = getattr(il.arch, "cs_table_lift", None)
            if value is not None:
                return bool(value)
        except Exception:
            pass

        try:
            arch_name = builtins.str(getattr(il.arch, "name", "")).lower()
        except Exception:
            return True

        for suffix in self._cs_table_lift_disabled_suffixes:
            if arch_name.endswith(suffix):
                return False
        return True

    def _ret_pass_flags_enabled(self, il):
        # Respect explicit per-instance overrides first.
        try:
            explicit = getattr(il.arch, "__dict__", {}).get("ret_pass_flags", None)
            if explicit is not None:
                return bool(explicit)
        except Exception:
            pass

        # If the architecture explicitly opts in, honor that.
        try:
            if getattr(il.arch, "ret_pass_flags", None) is True:
                return True
        except Exception:
            pass

        # Core architectures (not python subclasses) may not expose plugin attrs.
        # Enable the behavior for known 16-bit x86 names when shadow regs exist.
        try:
            arch_name = builtins.str(getattr(il.arch, "name", "")).lower()
            if arch_name not in self._ret_pass_flag_arch_names:
                return False
        except Exception:
            return False

        for flag in self._ret_status_flags(il):
            if self._ret_shadow_register_for_flag(il, flag) is None:
                return False
        return True

    def _ret_status_flags(self, il):
        try:
            arch_flags = getattr(il.arch, "ret_status_flags", None)
            if isinstance(arch_flags, (tuple, list)):
                return tuple(flag for flag in arch_flags if isinstance(flag, builtins.str))
        except Exception:
            pass
        return self._default_ret_status_flags

    def _ret_shadow_register_for_flag(self, il, flag):
        try:
            reg_map = getattr(il.arch, "ret_flag_shadow_regs", None)
            if not isinstance(reg_map, dict):
                reg_map = self._default_ret_flag_shadow_regs
            reg = reg_map.get(flag)
            if not isinstance(reg, builtins.str):
                return None
            regs = getattr(il.arch, "regs", None)
            if isinstance(regs, dict) and reg not in regs:
                return None
            return reg
        except Exception:
            return None

    def _lift_shadow_status_flags(self, il):
        if not self._ret_pass_flags_enabled(il):
            return

        arch_flags = getattr(il.arch, "flags", ())
        for flag in self._ret_status_flags(il):
            if flag not in arch_flags:
                continue
            shadow_reg = self._ret_shadow_register_for_flag(il, flag)
            if shadow_reg is None:
                continue
            il.append(il.set_reg(1, shadow_reg, il.flag(flag)))

    def _lift_restore_status_flags(self, il):
        if not self._ret_pass_flags_enabled(il):
            return

        arch_flags = getattr(il.arch, "flags", ())
        for flag in self._ret_status_flags(il):
            if flag not in arch_flags:
                continue
            shadow_reg = self._ret_shadow_register_for_flag(il, flag)
            if shadow_reg is None:
                continue
            il.append(il.set_flag(flag, il.reg(1, shadow_reg)))

    def _lift_load_far(self, il, addr):
        seg_off = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(4, seg_off, self._lift_mem_load(il, 4, addr)))
        seg     = LLIL_TEMP(il.temp_reg_count)
        seg_value = il.logical_shift_right(4, il.reg(4, seg_off), il.const(1, 16))
        il.append(il.set_reg(2, seg, il.low_part(2, seg_value)))
        off     = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, off, il.low_part(2, il.reg(4, seg_off))))
        return il.reg(2, seg), il.reg(2, off)

    def _lift_mem_byte_addr(self, il, addr, byte_offset):
        if byte_offset == 0:
            return addr
        result = il.add(3, addr, il.const(3, byte_offset))
        if a20_gate:
            result = il.and_expr(3, il.const(3, 0xfffff), result)
        return result

    def _lift_mem_load(self, il, size, addr):
        """Load little-endian memory with the 8086's 20-bit bus wrap."""
        if size == 1:
            return il.load(1, addr)

        result = il.zero_extend(size, il.load(1, addr))
        for byte_offset in range(1, size):
            byte = il.load(1, self._lift_mem_byte_addr(il, addr, byte_offset))
            byte = il.zero_extend(size, byte)
            byte = il.shift_left(size, byte, il.const(1, byte_offset * 8))
            result = il.or_expr(size, result, byte)
        return result

    def _lift_mem_store(self, il, size, addr, value):
        """Store little-endian memory with the 8086's 20-bit bus wrap."""
        if size == 1:
            il.append(il.store(1, addr, value))
            return

        # Cache once: arithmetic values may write flags and may themselves load
        # the destination, so re-evaluating per byte would be incorrect.
        cached = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(size, cached, value))
        for byte_offset in range(size):
            byte = il.logical_shift_right(
                size, il.reg(size, cached), il.const(1, byte_offset * 8)
            )
            byte = il.low_part(1, byte)
            byte_addr = self._lift_mem_byte_addr(il, addr, byte_offset)
            il.append(il.store(1, byte_addr, byte))

    def _lift_flags_word(self, il):
        # The original 8086 manual specifies reserved FLAGS bits as
        # indeterminate when stored.  Keep the defined flag bits precise while
        # avoiding later-processor fixed-bit assumptions.
        reserved = il.and_expr(2, il.undefined(), il.const(2, 0xf02a))
        flags = reserved
        for flag, flag_bit in flags_bits:
            flags = il.or_expr(2, il.flag_bit(2, flag, flag_bit), flags)
        return flags

    def _lift_interrupt(self, il, addr, instr_len, number):
        """Save real-mode state and transfer through an interrupt vector."""
        il.append(il.push(2, self._lift_flags_word(il)))
        il.append(il.set_flag('t', il.const(1, 0)))
        il.append(il.set_flag('i', il.const(1, 0)))
        il.append(il.push(2, il.reg(2, 'cs')))
        return_ip = self._near_target(addr, instr_len, 0) & 0xffff
        il.append(il.push(2, il.const(2, return_ip)))
        vector_addr = self._const_addr(il, builtins.int(number) * 4)
        cs, ip = self._lift_load_far(il, vector_addr)
        il.append(il.set_reg(2, 'cs', cs))
        il.append(il.jump(self._lift_phys_addr(il, cs, ip)))


class Prefix(Instruction):
    def decode(self, decoder, addr):
        Instruction.decode(self, decoder, addr)
        try:
            self.next = Instruction(decoder)
        except KeyError:
            self.next = Instruction()
        self.next.decode(decoder, self._near_target(addr, self.length(), 0))

    def encode(self, encoder, addr):
        Instruction.encode(self, encoder, addr)
        self.next.encode(encoder, self._near_target(addr, self.length(), 0))

    def total_length(self):
        return self.length() + self.next.total_length()

    def terminal_instruction(self):
        instr = self.next
        while isinstance(instr, Prefix):
            instr = instr.next
        return instr

    def terminal_addr(self, addr):
        instr = self
        while isinstance(instr, Prefix):
            addr = instr._near_target(addr, instr.length(), 0)
            instr = instr.next
        return instr, addr

    def analyze(self, info, addr):
        Instruction.analyze(self, info, addr)
        self.next.analyze(info, self._near_target(addr, self.length(), 0))

    def render(self, addr):
        return self.next.render(self._near_target(addr, self.length(), 0))

    def lift(self, il, addr):
        self.next.lift(il, self._near_target(addr, self.length(), 0))


class InstrHasWidth(object):
    def width(self):
        return 1 + (self.opcode & 0b1)

    def _regW(self):
        if self.width() == 2:
            return reg16
        else:
            return reg8


class Instr16Bit(object):
    def width(self):
        return 2

    def _regW(self):
        return reg16


class InstrHasImm(object):
    def length(self):
        return super(InstrHasImm, self).length() + self.width()

    def decode(self, decoder, addr):
        super(InstrHasImm, self).decode(decoder, addr)
        self.imm = decoder.immediate(self.width())

    def encode(self, encoder, addr):
        super(InstrHasImm, self).encode(encoder, addr)
        encoder.immediate(self.imm, self.width())


class InstrHasSegment(object):
    segment_override = None

    def segment(self):
        if self.segment_override:
            return self.segment_override
        else:
            return self._default_segment()

    def _default_segment(self):
        return 'ds'

class InstrHasDisp(InstrHasSegment):
    def length(self):
        return Instruction.length(self) + 2

    def decode(self, decoder, addr):
        Instruction.decode(self, decoder, addr)
        self.disp = decoder.displacement(2)

    def encode(self, encoder, addr):
        Instruction.encode(self, encoder, addr)
        encoder.displacement(self.disp, 2)

    def _render_mem(self):
        tokens = asm(
            ('beginMem', '[')
        )
        if self.segment() != self._default_segment():
            tokens += asm(
                ('reg', self.segment()),
                ('opsep', ':')
            )
        tokens += asm(
            ('addr', fmt_disp(self.disp), self.disp),
            ('endMem', ']'),
        )
        return tokens

    def _lift_mem(self, il):
        w = self.width()
        phys = self._lift_phys_addr(il, self.segment(), il.const(2, self.disp))
        return self._lift_mem_load(il, w, phys)

    def _lift_set_mem(self, il, value):
        phys = self._lift_phys_addr(il, self.segment(), il.const(2, self.disp))
        self._lift_mem_store(il, self.width(), phys, value)


class InstrHasModRegRM(InstrHasSegment):
    def length(self):
        return super(InstrHasModRegRM, self).length() + 1 + self._disp_length()

    def decode(self, decoder, addr):
        super(InstrHasModRegRM, self).decode(decoder, addr)
        self._mod_reg_rm = decoder.unsigned_byte()
        self.disp = decoder.displacement(self._disp_length())

    def encode(self, encoder, addr):
        super(InstrHasModRegRM, self).encode(encoder, addr)
        encoder.unsigned_byte(self._mod_reg_rm)
        encoder.displacement(self.disp, self._disp_length())

    def _default_segment(self):
        if self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110:
            return 'ds'
        elif self._mod_bits() != 0b11 and 'bp' in self._mem_regs():
            return 'ss'
        else:
            return 'ds'

    def _mod_bits(self):
        return self._mod_reg_rm >> 6

    def _reg_bits(self):
        return (self._mod_reg_rm >> 3) & 0b111

    def _reg_mem_bits(self):
        return self._mod_reg_rm & 0b111

    def _reg(self):
        return self._regW()[self._reg_bits()]

    def _mem_regs(self):
        return regs_rm[self._reg_mem_bits()]

    def _reg2(self):
        return self._regW()[self._reg_mem_bits()]

    def _disp_length(self):
        if self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110:
            return 2
        elif self._mod_bits() == 0b10:
            return 2
        elif self._mod_bits() == 0b01:
            return 1
        return 0

    def _render_reg_mem(self, fixed_width=False):
        if self._mod_bits() == 0b11:
            return asm(
                ('reg', self._reg2())
            )
        elif self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110:
            disp = self.disp & 0xffff
            tokens = [
                ('int', fmt_disp(disp), disp)
            ]
        else:
            tokens = [('reg', reg) for reg in self._mem_regs()]
            if len(tokens) == 2:
                tokens.insert(1, ('text', '+'))
            if self._mod_bits() != 0b00:
                tokens += [
                    ('int', fmt_hex_sign(self.disp), self.disp)
                ]
        if self.segment() != self._default_segment():
            tokens = [
                ('reg', self.segment()),
                ('opsep', ':')
            ] + tokens
        tokens = [
            ('beginMem', '[')
        ] + tokens + [
            ('endMem', ']')
        ]
        if not fixed_width:
            tokens = [
                ('text', op_width[self.opcode & 0b1]),
                ('opsep', ' '),
            ] + tokens
        return asm(*tokens)

    def _lift_reg_mem(self, il, only_calc_addr=False):
        if self._mod_bits() == 0b11:
            if only_calc_addr:
                # MOD=11 is not expressly prohibited for LEA in the manual.
                return il.reg(2, self._reg2())
            return il.reg(self.width(), self._reg2())
        elif self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110:
            offset = il.const(2, self.disp & 0xffff)
        else:
            offsets = [il.reg(2, reg) for reg in self._mem_regs()]
            if self._mod_bits() != 0b00:
                offsets.append(il.const(2, self.disp))
            offset = reduce(lambda expr, reg: il.add(2, expr, reg), offsets)
        if only_calc_addr:
            return offset
        phys = self._lift_phys_addr(il, self.segment(), offset)
        return self._lift_mem_load(il, self.width(), phys)

    def _lift_set_reg_mem(self, il, value):
        if self._mod_bits() == 0b11:
            il.append(il.set_reg(self.width(), self._reg2(), value))
            return
        phys = self._lift_reg_mem_addr(il)
        self._lift_mem_store(il, self.width(), phys, value)

    def _lift_reg_mem_addr(self, il):
        """Return the physical address of a memory operand without loading it."""
        if self._mod_bits() == 0b11:
            return None
        offset = self._lift_reg_mem(il, only_calc_addr=True)
        return self._lift_phys_addr(il, self.segment(), offset)
