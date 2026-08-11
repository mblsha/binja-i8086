from binaryninja.enums import BranchType
from binaryninja.lowlevelil import LLIL_TEMP

from ..helpers import *
from ..tables import *
from . import *


__all__ = ['CallFarImm', 'CallFarMem', 'CallNearImm', 'CallNearRM']


class Call(Instruction):
    def name(self):
        return 'call'


class CallFarImm(Call):
    def length(self):
        return 5

    def decode(self, decoder, addr):
        Call.decode(self, decoder, addr)
        self.ip = decoder.unsigned_word()
        self.cs = decoder.unsigned_word()

    def encode(self, encoder, addr):
        Call.encode(self, encoder, addr)
        encoder.unsigned_word(self.ip)
        encoder.unsigned_word(self.cs)

    def target(self):
        return ((self.cs << 4) + self.ip) & 0xfffff

    def analyze(self, info, addr):
        Call.analyze(self, info, addr)
        info.add_branch(BranchType.CallDestination, self.target())

    def render(self, addr):
        tokens = Call.render(self, addr)
        tokens += asm(
            ('addr', fmt_code_abs(self.cs), self.cs << 4),
            ('opsep', ':'),
            ('addr', fmt_code_abs(self.ip), self.target()),
        )
        return tokens

    def lift(self, il, addr):
        # A far call pushes CS before the ordinary return IP.  LLIL_CALL
        # abstracts the callee and resumes on the returned path, so restore the
        # caller's CS there while the extra stack adjustment models RETF's CS
        # pop.
        temp = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, temp, il.reg(2, 'cs')))
        il.append(il.push(2, il.reg(2, 'cs')))
        il.append(il.set_reg(2, 'cs', il.const(2, self.cs)))
        il.append(il.call_stack_adjust(il.const(3, self.target()), 2))
        il.append(il.set_reg(2, 'cs', il.reg(2, temp)))
        self._lift_restore_status_flags(il)


class CallFarMem(InstrHasModRegRM, Instr16Bit, Call):
    def analyze(self, info, addr):
        Call.analyze(self, info, addr)
        info.add_branch(BranchType.CallDestination)

    def render(self, addr):
        if self._mod_bits() == 0b11:
            return asm(('instr', '(unassigned)'))

        tokens = Call.render(self, addr)
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

        cs, ip = self._lift_load_far(il, self._lift_reg_mem_addr(il))
        old_cs = LLIL_TEMP(il.temp_reg_count)
        il.append(il.set_reg(2, old_cs, il.reg(2, 'cs')))
        il.append(il.push(2, il.reg(2, old_cs)))
        il.append(il.set_reg(2, 'cs', cs))
        il.append(il.call_stack_adjust(self._lift_phys_addr(il, cs, ip), 2))
        il.append(il.set_reg(2, 'cs', il.reg(2, old_cs)))
        self._lift_restore_status_flags(il)


class CallNearImm(Call):
    def length(self):
        return 3

    def decode(self, decoder, addr):
        Call.decode(self, decoder, addr)
        self.ip = self._near_target(addr, self.length(), decoder.signed_word())

    def encode(self, encoder, addr):
        Call.encode(self, encoder, addr)
        encoder.signed_word(self._near_displacement(addr, self.length(), self.ip))

    def analyze(self, info, addr):
        Call.analyze(self, info, addr)
        info.add_branch(BranchType.CallDestination, self.ip)

    def render(self, addr):
        ip_rel = self._near_displacement(addr, 0, self.ip)
        tokens = Call.render(self, addr)
        tokens += asm(
            ('codeRelAddr', fmt_code_rel(ip_rel), self.ip),
        )
        return tokens

    def lift(self, il, addr):
        il.append(il.call(self._const_addr(il, self.ip)))
        self._lift_restore_status_flags(il)


class CallNearRM(InstrHasModRegRM, Instr16Bit, Call):
    def analyze(self, info, addr):
        Call.analyze(self, info, addr)
        info.add_branch(BranchType.CallDestination)

    def render(self, addr):
        tokens = Call.render(self, addr)
        tokens += self._render_reg_mem()
        return tokens

    def _try_build_synthetic_callvec_target(self, view, slot_addr):
        """Fallback target for runtime-patched callvec slots.

        Some overlays keep callvec entries zero in static flat images and patch them
        at runtime. When we can identify the slot symbol, route the call to a stable
        synthetic target so HLIL can render a semantic call name instead of a large
        segmented pointer expression.
        """

        slot_addr = slot_addr & 0xfffff
        slot_low = slot_addr & 0xffff
        try:
            get_symbol_at = getattr(view, "get_symbol_at", None)
            symbol = get_symbol_at(slot_addr) if callable(get_symbol_at) else None
            if symbol is None and callable(get_symbol_at):
                # Compatibility fallback for views that still attach these symbols
                # to low 16-bit addresses.
                symbol = get_symbol_at(slot_low)
        except Exception:
            symbol = None
        if symbol is None:
            return None

        name = getattr(symbol, "raw_name", None) or getattr(symbol, "name", None) or ""
        if "callvec" not in str(name).lower():
            return None

        synth_addr = (0xF0000 + slot_low) & 0xfffff

        try:
            get_symbol_at = getattr(view, "get_symbol_at", None)
            existing = get_symbol_at(synth_addr) if callable(get_symbol_at) else None
            if existing is None:
                define_auto_symbol = getattr(view, "define_auto_symbol", None)
                if callable(define_auto_symbol):
                    from binaryninja import Symbol
                    from binaryninja.enums import SymbolType

                    define_auto_symbol(Symbol(SymbolType.FunctionSymbol, synth_addr, str(name)))
        except Exception:
            pass

        return synth_addr

    def _try_resolve_cs_call_table_target(self, il, addr):
        if self._mod_bits() == 0b11:
            return None
        if not (self._mod_bits() == 0b00 and self._reg_mem_bits() == 0b110):
            return None
        if self.segment_override != "cs":
            return None

        view = self._view_from_il(il)
        if view is None:
            return None

        segment_base = self._segment_base_for_addr(view, addr)
        slot_addr = (segment_base + (self.disp & 0xffff)) & 0xfffff
        target_off = self._read_u16(view, slot_addr)
        if target_off is None:
            return None
        # Zero call-table entries are frequently runtime-patched placeholders.
        # Route known callvec slots to synthetic semantic targets.
        if target_off == 0:
            return self._try_build_synthetic_callvec_target(view, slot_addr)
        return (segment_base + target_off) & 0xfffff

    def lift(self, il, addr):
        if self._cs_table_lift_enabled(il):
            resolved = self._try_resolve_cs_call_table_target(il, addr)
            if resolved is not None:
                il.append(il.call(self._const_addr(il, resolved)))
                self._lift_restore_status_flags(il)
                return

        target_off = self._lift_reg_mem(il)
        il.append(il.call(self._lift_phys_addr(il, 'cs', target_off)))
        self._lift_restore_status_flags(il)
