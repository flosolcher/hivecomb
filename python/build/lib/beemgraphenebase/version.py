"""Version reported to code that checks it.

Deliberately **not** beem's `0.24.26`. Anything that branches on the version
should see that it is talking to hivecomb, not to beem.
"""

import hivecomb

version = f"hivecomb-compat-{hivecomb.__version__}"
