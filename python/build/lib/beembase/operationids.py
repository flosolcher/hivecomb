"""Operation ids.

Drop-in for `beembase.operationids`, with the table corrected.

beem shipped two lists and used the wrong one:

* The active ``ops`` list predates HF25. It contains neither
  ``collateralized_convert`` (48) nor ``recurrent_transfer`` (49), so beem cannot
  construct either operation — and because those two non-virtual operations are
  missing, **every virtual operation id it reports is two lower than the
  chain's**. ``fill_convert_request`` is 50 on chain and 48 in beem;
  ``producer_reward`` is 64 on chain and 62 in beem.
* The ``ops_HF25`` list, which the file invites you to enable, contains a
  **missing comma**::

      'convert',
      'collateralized_convert'      # <- no comma
      'account_create',

  Python concatenates adjacent string literals, so that is the single element
  ``'collateralized_convertaccount_create'``. The list loses two names, gains one
  nonsense name, and shifts every id from index 10 onward by one. It also inserts
  the new operations in the middle rather than appending them, renumbering
  everything after — the opposite of what hived did.

Both are findings 1 and 2. The table below is generated from hived's
``operations.hpp`` and matches the chain.

Note that ``ops`` and ``ops_HF25`` are the same list here. There is no second
list to fall out of sync with.
"""

from __future__ import annotations

import hivecomb

#: Every operation, indexed by its id in hived's static variant.
#:
#: **Derived from Rust, not written here.** `hivecomb.operation_names()` returns the
#: same table `hivecomb` serializes with, so this list cannot disagree with the bytes
#: that actually go on the wire. beem's failure mode was precisely a second copy: it
#: shipped two tables, used the pre-HF25 one, and the other had a missing comma that
#: concatenated two names and shifted every id after it (findings 1 and 2). A table
#: with one owner cannot drift from itself.
ops = list(hivecomb.operation_names())

#: beem shipped this as a separate, broken list. Kept as an alias so code that
#: imports it keeps working, and correct because it is the same table.
ops_HF25 = ops

#: The lowest virtual operation id.
FIRST_VIRTUAL_OP = 50

operations = {name: index for index, name in enumerate(ops)}

#: beem's spelling of ``recurrent_transfer``, accepted as an alias.
operations["recurring_transfer"] = operations["recurrent_transfer"]


def getOperationNameForId(i):
    """Convert an operation id into its name.

    beem compared with ``is`` rather than ``==`` (finding 18), which worked only
    because CPython interns small integers.
    """
    i = int(i)
    if 0 <= i < len(ops):
        return ops[i]
    return "Unknown Operation ID %d" % i


def getOperationIdForName(name):
    """Convert an operation name into its id."""
    name = name.replace("_operation", "")
    if name not in operations:
        raise ValueError(f"unknown operation {name!r}")
    return operations[name]


def isVirtualOperation(name_or_id):
    """Whether the chain emits this operation rather than accepting it."""
    if isinstance(name_or_id, str):
        name_or_id = getOperationIdForName(name_or_id)
    return int(name_or_id) >= FIRST_VIRTUAL_OP
