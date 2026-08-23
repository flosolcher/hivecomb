"""Re-export the compiled extension.

maturin generates this file when it is absent. It is checked in instead so that
`py.typed` and `__init__.pyi` can sit beside it inside the importable package —
PEP 561 requires the marker to be *in* the package, and files merely included in
the wheel at another path are invisible to a type checker.
"""

from .hivecomb import *  # noqa: F401,F403
from . import hivecomb as _ext

__doc__ = _ext.__doc__
if hasattr(_ext, "__all__"):
    __all__ = _ext.__all__
