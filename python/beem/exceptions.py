"""Exceptions.

Drop-in for `beem.exceptions`. The names and hierarchy match beem's, so
``except AccountDoesNotExistsException`` keeps working.
"""


class BeemException(Exception):
    """Base for everything raised by this layer."""


class WalletExists(BeemException):
    """A wallet already exists at that path."""


class WalletLocked(BeemException):
    """The wallet is locked."""


class NoWalletException(BeemException):
    """No wallet has been created."""


class OfflineHasNoRPCException(BeemException):
    """An operation needing a node was attempted while offline."""


class AccountExistsException(BeemException):
    """The account already exists."""


class AccountDoesNotExistsException(BeemException):
    """The account does not exist on chain."""


class AssetDoesNotExistsException(BeemException):
    """The asset is not one this chain knows."""


class InvalidAssetException(BeemException):
    """The asset is not valid in this context."""


class InsufficientAuthorityError(BeemException):
    """The keys available cannot satisfy the required authority."""


class MissingKeyError(BeemException):
    """A key needed for this operation is not available."""


class InvalidWifError(BeemException):
    """The WIF could not be parsed."""


class InvalidMemoKeyException(BeemException):
    """The memo key is not valid."""


class WrongMemoKey(BeemException):
    """The memo cannot be decrypted with the key given."""


class BlockDoesNotExistsException(BeemException):
    """The node does not have that block."""


class ContentDoesNotExistsException(BeemException):
    """No such post or comment."""


class VotingInvalidOnArchivedPost(BeemException):
    """The payout window has closed."""


class WitnessDoesNotExistsException(BeemException):
    """No such witness."""


class VoteDoesNotExistsException(BeemException):
    """No such vote."""


class NoWriteAccess(BeemException):
    """This instance was created read-only."""


class RPCConnectionRequired(BeemException):
    """A node connection is required and none is configured."""


class WrongMasterPasswordException(BeemException):
    """The wallet passphrase is wrong."""


class ObjectNotInProposalBuffer(BeemException):
    """The object is not in the proposal buffer."""


class TransactionExpiredException(BeemException):
    """The transaction expired before it was accepted."""


class KeyAlreadyInStoreException(BeemException):
    """That key is already in the wallet."""


class KeyNotFound(BeemException):
    """That key is not in the wallet."""


class OfflineHasNoRPC(OfflineHasNoRPCException):
    """Alias kept for compatibility."""
