"""Version reported to code that checks it.

Deliberately not beem's ``0.24.26``: anything branching on the version should be
able to tell it is talking to comb.
"""

import comb

version = f"comb-compat-{comb.__version__}"
