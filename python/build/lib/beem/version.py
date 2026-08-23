"""Version reported to code that checks it.

Deliberately not beem's ``0.24.26``: anything branching on the version should be
able to tell it is talking to hivecomb.
"""

import hivecomb

version = f"hivecomb-compat-{hivecomb.__version__}"
