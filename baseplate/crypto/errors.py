"""Errors for common cryptographic operations failing."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class SignatureError(Exception):
    """Base class for all message signing related errors."""

    pass


class UnreadableSignatureError(SignatureError):
    """Raised when the signature is corrupt or wrongly formatted."""

    pass


class IncorrectSignatureError(SignatureError):
    """Raised when the signature is readable but does not match the message."""

    pass


class ExpiredSignatureError(SignatureError):
    """Raised when the signature is valid but has expired.

    The ``expiration`` attribute is the time (as seconds since the UNIX epoch)
    at which the signature expired.

    """

    def __init__(self, expiration):
        self.expiration = expiration
        super(ExpiredSignatureError, self).__init__()


class UnparseableTokenError(Exception):
    pass


class CorruptTokenError(Exception):
    def __init__(self, message, plaintext_id, plaintext_version,
                 plaintext_created):
        self.plaintext_id = plaintext_id
        self.plaintext_version = plaintext_version
        self.plaintext_created = plaintext_created

        super(CorruptTokenError, self).__init__(self, message)


class InvalidTokenError(Exception):
    def __init__(self, message, plaintext_id, plaintext_version,
                 plaintext_created, encrypted_id, encrypted_version,
                 encrypted_created):
        self.plaintext_id = plaintext_id
        self.plaintext_version = plaintext_version
        self.plaintext_created = plaintext_created

        self.encrypted_id = encrypted_id
        self.encrypted_version = encrypted_version
        self.encrypted_created = encrypted_created

        super(InvalidTokenError, self).__init__(self, message)
