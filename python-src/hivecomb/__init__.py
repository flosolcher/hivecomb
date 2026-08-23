"""Re-export the compiled extension.

maturin generates this file when it is absent. It is checked in instead so that
`py.typed` and `__init__.pyi` can sit beside it inside the importable package —
PEP 561 requires the marker to be *in* the package, and a file merely included in
the wheel at another path is invisible to a type checker.

`__all__` is declared explicitly because Python binds a submodule as an attribute
of its parent on import, so `dir(hivecomb)` also contains `hivecomb` — the
extension itself, reachable as `hivecomb.hivecomb`. That is an artifact of the
package layout, not API, and without `__all__` it makes the module's surface
depend on how it was installed: 20 names from a bare `.so` on `PYTHONPATH`, 21
from the wheel. An integrator pinning on a capability tuple would see the two
disagree for no reason. Reported by one who did.
"""

from .hivecomb import *  # noqa: F401,F403
from . import hivecomb as _extension

__doc__ = _extension.__doc__
__version__ = _extension.__version__

#: The public surface, identical however the package was installed.
__all__ = [name for name in dir(_extension) if not name.startswith("_")]
