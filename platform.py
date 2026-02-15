from binaryninja import Architecture, Platform


__all__ = ['Dos']


class Dos(Platform):
    name = 'dos-8086'


def _set_platform_defaults_for_arch(arch_name):
    try:
        arch = Architecture[arch_name]
    except KeyError:
        return

    regparm = arch.calling_conventions.get('regparm')
    regcall = arch.calling_conventions.get('regcall')
    default_cc = regparm or regcall
    cdecl = arch.calling_conventions.get('cdecl')
    if default_cc is None:
        return

    for platform in Platform:
        if platform.arch == arch:
            platform.default_calling_convention = default_cc
            if cdecl is not None:
                platform.cdecl_calling_convention = cdecl


arch = Architecture['8086']

dos = Dos(arch)
dos.default_calling_convention = (
    arch.calling_conventions.get('regparm')
    or arch.calling_conventions.get('regcall')
    or arch.calling_conventions['default']
)
dos.cdecl_calling_convention = arch.calling_conventions['cdecl']
dos.register('dos')

_set_platform_defaults_for_arch('8086')
_set_platform_defaults_for_arch('8086-vanilla')
_set_platform_defaults_for_arch('x86_16')
