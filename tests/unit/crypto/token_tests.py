import base64
from datetime import datetime
import unittest

from cryptography.fernet import Fernet

from baseplate.secrets import VersionedSecret
from baseplate.crypto import token as encrypted_token_module
from baseplate.crypto.token import crypt64, decrypt64, EncryptedToken
from baseplate.crypto.errors import (
    CorruptTokenError,
    InvalidTokenError,
    UnparseableTokenError,
)
from baseplate.crypto.common import from_epoch_milliseconds, UTC

from .. import mock


class TestCrypto(unittest.TestCase):
    """Test LoId payload encryption functions."""

    def setUp(self):
        super(TestCrypto, self).setUp()
        self.cipher = Fernet(Fernet.generate_key())

    def test_crypt_idempotent(self):
        """Test encryption followed by decryption is idempotent."""
        payload = "hello world"
        cryptoblob = crypt64(self.cipher, payload)
        payload_copy = decrypt64(self.cipher, cryptoblob)
        self.assertEqual(payload, payload_copy)

    def test_bad_payload(self):
        """Test bad data fails to decrypt."""
        payload = "hello world"
        cryptoblob = crypt64(self.cipher, payload)
        with self.assertRaises(ValueError):
            decrypt64(self.cipher, "deadbeef" + cryptoblob)

    def test_really_bad_payload(self):
        """Test non-base64 data fails to decrypt."""
        with self.assertRaises(ValueError):
            decrypt64(self.cipher, "I'm not even base64!")

    def test_fake_payload(self):
        """Test garbage payloads fail properly."""
        with self.assertRaises(ValueError):
            payload = "This is total garbage."
            decrypt64(
                self.cipher,
                base64.urlsafe_b64encode(payload.encode("utf-8"))
            )


class EncryptedTokenTests(unittest.TestCase):
    def setUp(self):
        super(EncryptedTokenTests, self).setUp()
        self.secret = VersionedSecret.from_simple_secret(Fernet.generate_key())
        self.cipher = Fernet(self.secret.current)
        self.autopatch(EncryptedToken, "get_cipher", return_value=self.cipher)

    def autopatch(self, obj, attr, *a, **kw):
        """Helper method to patch an object and automatically cleanup."""
        p = mock.patch.object(obj, attr, *a, **kw)
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def test_serialize_token(self):
        ID = "abcdefghijklmnopqr"
        EPOCH_MS = 123
        CREATED = datetime(2017, 3, 28, 0, 0, 0, 0, tzinfo=UTC)
        VERSION = 3
        PAYLOAD = "payload"
        CRYPTOBLOB = "encrypted"

        to_epoch_milliseconds = self.autopatch(
            encrypted_token_module, "to_epoch_milliseconds",
            mock.MagicMock(return_value=EPOCH_MS))
        mock_crypt64 = self.autopatch(
            encrypted_token_module, "crypt64",
            mock.MagicMock(return_value=CRYPTOBLOB))

        token = EncryptedToken(
            self.secret,
            token_id=ID,
            version=VERSION,
            created=CREATED,
            payload=PAYLOAD,
        )
        serialized = token.serialize()

        to_epoch_milliseconds.assertCalledWith(CREATED)

        blob = "{token_id}.{version}.{created}.{payload}".format(
            self.secret,
            token_id=ID,
            version=VERSION,
            created=EPOCH_MS,
            payload=PAYLOAD,
        )

        mock_crypt64.assertCalledWith(blob)

        expected = "{token_id}.{version}.{created}.{cryptoblob}".format(
            self.secret,
            token_id=ID,
            version=VERSION,
            created=EPOCH_MS,
            cryptoblob=CRYPTOBLOB,
        )

        self.assertEqual(serialized, expected)

    def test_parse_token_str(self):
        ID = "0123456789abcdefgh"
        VERSION = 3000
        EPOCH_MS = 1490579271300
        CREATED = from_epoch_milliseconds(EPOCH_MS)
        CRYPTOBLOB = "cryptoblob"
        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, CRYPTOBLOB)
        ret = EncryptedToken.parse_token_str(token_str)
        self.assertEqual(ret, (ID, VERSION, CREATED, CRYPTOBLOB))

    def test_parse_token_str_bad_id(self):
        # ids must be a-zA-Z0-9, 18 characters long
        TOO_SHORT_ID = "abc"
        token_str = "%s.3.1490579271300.cryptoblob" % TOO_SHORT_ID
        with self.assertRaises(UnparseableTokenError):
            EncryptedToken.parse_token_str(token_str)

        NON_ALPHANUMERIC_ID = "*&^$ab"
        token_str = "%s.3.1490579271300.cryptoblob" % NON_ALPHANUMERIC_ID
        with self.assertRaises(UnparseableTokenError):
            EncryptedToken.parse_token_str(token_str)

    def test_parse_token_str_bad_version(self):
        # version can only contain numbers
        BAD_VERSION = "abc"
        token_str = (
            "0123456789abcdefgh.%s.1490579271300.cryptoblob" % BAD_VERSION
        )
        with self.assertRaises(UnparseableTokenError):
            EncryptedToken.parse_token_str(token_str)

    def test_parse_token_str_bad_epoch_ms(self):
        # epoch_ms can only contain numbers
        BAD_EPOCH_MS = "abc"
        token_str = "0123456789abcdefgh.3.%s.cryptoblob" % BAD_EPOCH_MS
        with self.assertRaises(UnparseableTokenError):
            EncryptedToken.parse_token_str(token_str)

    def test_parse_token_str_bad_cryptoblob(self):
        # cryptoblob can only contain a-zA-Z0-9-_
        BAD_CRYPTOBLOB = "!!!"
        token_str = "0123456789abcdefgh.3.1490579271300.%s" % BAD_CRYPTOBLOB
        with self.assertRaises(UnparseableTokenError):
            EncryptedToken.parse_token_str(token_str)

    def test_deserialize_token(self):
        TOKEN_STR = "this is the token string"
        ID = "abcdefghijklmnopqr"
        VERSION = 3
        EPOCH_MS = 123
        CREATED = datetime(2017, 3, 28, 0, 0, 0, 0, tzinfo=UTC)
        CRYPTOBLOB = "encrypted"
        PAYLOAD = "payload"

        parse_token_str = self.autopatch(EncryptedToken, "parse_token_str")
        parse_token_str.return_value = (ID, VERSION, CREATED, CRYPTOBLOB)

        mock_decrypt64 = self.autopatch(encrypted_token_module, "decrypt64")
        # NOTE: the returned EPOCH_MS here doesn't really matter, because it's
        # set to the correct value by the from_epoch_milliseconds patch
        mock_decrypt64.return_value = '.'.join(
            str(i) for i in (ID, VERSION, EPOCH_MS, PAYLOAD))

        mock_from_epoch_milliseconds = self.autopatch(
            encrypted_token_module, "from_epoch_milliseconds")
        mock_from_epoch_milliseconds.return_value = CREATED

        # NOTE: the string passed here isn't used because the correct value is
        # returned by the parse_token_str patch. this lets us avoid re-testing
        # the parsing/regex functions
        token = EncryptedToken.deserialize(self.secret, TOKEN_STR)

        parse_token_str.assertCalledWith(TOKEN_STR)
        mock_decrypt64.assertCalledWith(CRYPTOBLOB)
        mock_from_epoch_milliseconds.assertCalledWith(EPOCH_MS)

        self.assertEqual(token.id, ID)
        self.assertEqual(token.version, VERSION)
        self.assertEqual(token.created, CREATED)
        self.assertEqual(token.payload, PAYLOAD)

    def test_deserialize_token_bad_cryptoblob(self):
        ID = "abcdefghijklmnopqr"
        VERSION = 3
        EPOCH_MS = 1490579271300
        BAD_CRYPTOBLOB = "not_a_valid_encrypted_string"

        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, BAD_CRYPTOBLOB)
        with self.assertRaises(CorruptTokenError):
            EncryptedToken.deserialize(self.secret, token_str)

    def test_deserialize_token_cryptobad_weird_payload(self):
        # payload must contain 3 periods (delimiting 4 fields)
        ID = "abcdefghijklmnopqr"
        VERSION = 3
        EPOCH_MS = 1490579271300

        NOT_ENOUGH_FIELDS = crypt64(self.cipher, "one.two.three")
        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, NOT_ENOUGH_FIELDS)
        with self.assertRaises(CorruptTokenError):
            EncryptedToken.deserialize(self.secret, token_str)

    def test_deserialize_token_cryptoblob_wrong_payload(self):
        # payload's id, version, created must match plaintext values
        ID = "abcdefghijklmnopqr"
        VERSION = 3
        EPOCH_MS = 1490579271300
        PAYLOAD = "payload"

        BAD_ID = "rqponmlkjihgfedcba"
        blob = "%s.%s.%s.%s" % (BAD_ID, VERSION, EPOCH_MS, PAYLOAD)
        cryptoblob = crypt64(self.cipher, blob)
        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, cryptoblob)
        with self.assertRaises(InvalidTokenError):
            EncryptedToken.deserialize(self.secret, token_str)

        BAD_VERSION = 4
        blob = "%s.%s.%s.%s" % (ID, BAD_VERSION, EPOCH_MS, PAYLOAD)
        cryptoblob = crypt64(self.cipher, blob)
        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, cryptoblob)
        with self.assertRaises(InvalidTokenError):
            EncryptedToken.deserialize(self.secret, token_str)

        BAD_EPOCH_MS = 1490579271301
        blob = "%s.%s.%s.%s" % (ID, VERSION, BAD_EPOCH_MS, PAYLOAD)
        cryptoblob = crypt64(self.cipher, blob)
        token_str = "%s.%s.%s.%s" % (ID, VERSION, EPOCH_MS, cryptoblob)
        with self.assertRaises(InvalidTokenError):
            EncryptedToken.deserialize(self.secret, token_str)
