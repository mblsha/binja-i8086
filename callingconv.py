from binaryninja import Architecture, CallingConvention, variable


__all__ = ['Intel8086CallingConvention',
           'RegisterOnlyCallingConvention',
           'CdeclCallingConvention',
           'PascalCallingConvention']


class Intel8086CallingConvention(CallingConvention):
    caller_saved_regs = ['ax', 'bx', 'cx', 'dx', 'es']
    callee_saved_regs = []
    int_arg_regs = []
    float_arg_regs = []
    int_return_reg = 'ax'
    high_int_return_reg = 'dx'
    float_return_reg = None
    global_pointer_reg = None
    implicitly_defined_regs = []

    def _has_arch_reg(self, reg):
        if not isinstance(reg, str):
            return False
        try:
            arch_regs = getattr(self.arch, "regs", None)
            return isinstance(arch_regs, dict) and reg in arch_regs
        except Exception:
            return False

    def perform_get_incoming_reg_value(self, reg, func):
        # BN may query pseudo-register names such as "invalid"/"top" for
        # register-stack metadata. They are not architectural registers for
        # 8086/x86_16 and should be treated as unknown.
        if not self._has_arch_reg(reg):
            return variable.Undetermined()
        try:
            return super().perform_get_incoming_reg_value(reg, func)
        except Exception:
            return variable.Undetermined()


class RegisterOnlyCallingConvention(Intel8086CallingConvention):
    int_arg_regs = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'ds', 'es']


class CdeclCallingConvention(Intel8086CallingConvention):
    stack_adjusted_on_return = False


class PascalCallingConvention(Intel8086CallingConvention):
    stack_adjusted_on_return = True


def _register_for_arch(arch_name):
    try:
        arch = Architecture[arch_name]
    except KeyError:
        return

    if 'default' not in arch.calling_conventions:
        arch.register_calling_convention(Intel8086CallingConvention(arch, 'default'))
    if 'regparm' not in arch.calling_conventions:
        arch.register_calling_convention(RegisterOnlyCallingConvention(arch, 'regparm'))
    if 'regcall' not in arch.calling_conventions:
        arch.register_calling_convention(RegisterOnlyCallingConvention(arch, 'regcall'))
    if 'cdecl' not in arch.calling_conventions:
        arch.register_calling_convention(CdeclCallingConvention(arch, 'cdecl'))
    if 'pascal' not in arch.calling_conventions:
        arch.register_calling_convention(PascalCallingConvention(arch, 'pascal'))

    arch.default_calling_convention = (
        arch.calling_conventions.get('regparm')
        or arch.calling_conventions.get('regcall')
        or arch.calling_conventions['default']
    )


_register_for_arch('8086')
_register_for_arch('8086-vanilla')
_register_for_arch('x86_16')
