import base64
import re
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

from . errors import UnparseableTokenError
from . errors import CorruptTokenError, InvalidTokenError
from . common import to_epoch_milliseconds, from_epoch_milliseconds, UTC


def crypt64(encryptor, payload):
    """Encrypt payload with Fernet.

    :param :py:class:`cryptography.fernet.Fernet` encryptor
    :param str payload: the data to be encrypted.
    :rtype: str
    :returns: a urlsafe base64 encoded string  with padding removed.
    """
    payload = payload.encode("utf-8")
    enc = encryptor.encrypt(payload)
    return base64.urlsafe_b64encode(enc).decode("utf-8").rstrip("=")


def decrypt64(decryptor, cryptoblob64):
    """Decrypt payload with Fernet.

    :param :py:class:`cryptography.fernet.Fernet` decryptor
    :param str cryptoblob64: A url safe base64 encoded blob of encrypted data
        without padding
    :rtype: str
    :returns: an unencrypted data blob as a str
    :raises: :py:exc:`ValueError` if the cryptoblob64 is invalid

    """

    try:
        # base64.urlsafe_b64decode raises an exception if the value you give
        # it is not type str, even if all of the characters are valid ascii.
        # Note that base64.b64decode does not have this issue.
        cryptoblob64 = str(cryptoblob64)
        # need to re-add the padding that was stripped by decrypt64
        padding = "=" * (len(cryptoblob64) % 4)
        with_padding = cryptoblob64 + padding
        cryptoblob = base64.urlsafe_b64decode(with_padding)
        return decryptor.decrypt(cryptoblob).decode("utf-8")
    except TypeError:
        raise ValueError("Invalid base64")
    except InvalidToken:
        raise ValueError("Invalid encrypted data")


class EncryptedToken(object):
    ID_LENGTH = 18
    TOKEN_RE = re.compile(
        r"""^
        (?P<prefix>                               # The prefix is 3 terms:
            (?P<id>[a-zA-Z0-9]{%(id_length)s})    # (1) Alphanumeric id
            \.                                    # "."
            (?P<version>\d+)                      # (2) version number
            \.                                    # "."
            (?P<created>\d+)                      # (3) epoch ms time (int)
        )                                         # </prefix>
        \.                                        # .
        (?P<cryptoblob>[a-zA-Z0-9-_]+)            # The cryptoblob is urlsafe
                                                  # Base64 with padding removed
        $""" % dict(id_length=ID_LENGTH),
        re.VERBOSE,
    )

    def __init__(
        self, secret, token_id, version=0, created=None, payload=None,
    ):
        self.secret = secret
        self.id = token_id
        self.version = version
        self.created = created or datetime.now(UTC)
        self.payload = payload

    @classmethod
    def get_cipher(cls, secret):
        """Helper function to get a ``Cipher``.

        :rtype: :py:class:`cryptography.fernet.Fernet`
        :returns: an encryptor or decryptor
        """
        return Fernet(secret.current)

    def serialize(self):
        """serialize and encrypt the EncryptedToken.

        Constructs a string which is of the form

            ${id}.${version}.${created}.${cryptoblob}

        The `cryptoblob` field is the encrypted form of

            ${id}.${version}.${created}.${payload}

        The duplication of the first three fields ensures that the
        token can be checked for tampering by comparing those values to the
        plaintext ones.

        :rtype: str
        :returns: serialized and encrypted EncryptedToken
        """
        created_ms = to_epoch_milliseconds(self.created)

        # the encrypted blob contains the plaintext portion of the token, for
        # later validation upon decryption
        blob = "{id}.{version}.{created}.{payload}".format(
            id=self.id,
            version=self.version,
            created=created_ms,
            payload=self.serialize_payload(),
        )
        encryptor = self.get_cipher(self.secret)
        cryptoblob = crypt64(encryptor, blob)

        return "{id}.{version}.{created}.{cryptoblob}".format(
            id=self.id,
            version=self.version,
            created=created_ms,
            cryptoblob=cryptoblob,
        )

    @classmethod
    def parse_token_str(cls, token_str):
        """Extract the fields from the token string.

        :param str token_str: string containing the :py:meth:`serialize`ed
            data.
        :rtype: tuple
        :returns: id, version, created, cryptoblob

        """
        # TODO: kind of weird that we enforce a strict format with the regex on
        # deserialization, but on serialization we can put whatever we want
        # into the string
        m = cls.TOKEN_RE.match(token_str)

        if not m:
            raise UnparseableTokenError

        groups = m.groupdict()

        try:
            token_id = groups['id']
            version = int(groups['version'])
            created = from_epoch_milliseconds(int(groups['created']))
            cryptoblob = groups['cryptoblob']
        except (KeyError, ValueError):
            # the group didn't exist or the value couldn't be coerced to the
            # correct type
            raise UnparseableTokenError

        return token_id, version, created, cryptoblob

    @classmethod
    def deserialize(cls, secret, token_str):
        """Decrypt and deserialize the EncryptedToken.

        :param str token_str: string containing the :py:meth:`serialize`ed
            data.
        :rtype: :py:class:`EncryptedToken`
        :returns: EncryptedToken decrypted and deserialized
        """
        token_id, version, created, cryptoblob = cls.parse_token_str(token_str)
        decryptor = cls.get_cipher(secret)

        try:
            blob = decrypt64(decryptor, cryptoblob)
        except ValueError:
            raise CorruptTokenError("decryption error", id, version, created)

        try:
            blob_id, blob_version, blob_created, payload = blob.split(".", 3)
        except ValueError:
            raise CorruptTokenError("bad blob", id, version, created)

        blob_version = int(blob_version)
        blob_created = from_epoch_milliseconds(int(blob_created))

        if (blob_id != token_id or
                blob_version != version or
                blob_created != created):
            raise InvalidTokenError(
                "mismatch",
                token_id,
                version,
                created,
                blob_id,
                blob_version,
                blob_created,
            )

        token = cls(
            secret=secret,
            token_id=token_id,
            version=version,
            created=created,
            payload=cls.deserialize_payload(payload),
        )

        return token

    @property
    def created_ms(self):
        return to_epoch_milliseconds(self.created)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.id)

    def to_dict(self, prefix=""):
        data = {
            "id": self.id,
            "created": self.created_ms,
            "version": self.version,
        }
        data.update(self.payload_to_dict())
        if prefix:
            data = {"_".join([prefix, k]): v for k, v in data.items()}
        return data

    @classmethod
    def from_str(cls, secret, token_str):
        try:
            return cls.deserialize(secret, token_str)
        except UnparseableTokenError:
            # the token was completely unreadable
            return
        except CorruptTokenError:
            # the token's encrypted blob was unreadable
            return
        except InvalidTokenError:
            # the token's blob and plaintext did not match
            return

    def to_str(self):
        return self.serialize()

    def serialize_payload(self):
        return self.payload

    @classmethod
    def deserialize_payload(self, payload_str):
        return payload_str

    def payload_to_dict(self):
        return {"payload": self.payload}
