try:
    from .architecture import *
    from .callingconv import *
    from .platform import *
    from .binaryview import *
except ImportError:
    # Allow direct module execution/import in unit-test environments where
    # this file may be imported as a top-level module instead of a package.
    from architecture import *
    from callingconv import *
    from platform import *
    from binaryview import *
