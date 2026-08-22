"""Version reported to code that checks it.

Deliberately **not** beem's `0.24.26`. Anything that branches on the version
should see that it is talking to comb, not to beem.
"""

import comb

version = f"comb-compat-{comb.__version__}"
