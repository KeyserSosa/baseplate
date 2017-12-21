import unittest

from cryptography.fernet import Fernet

from baseplate.secrets import VersionedSecret
from baseplate.crypto.errors import (
    CorruptTokenError,
    InvalidTokenError,
    UnparseableTokenError,
)
from baseplate.crypto.session import SessionTracker

from .. import mock


class SessionTrackerTests(unittest.TestCase):
    def setUp(self):
        super(SessionTrackerTests, self).setUp()
        self.secret = VersionedSecret.from_simple_secret(Fernet.generate_key())
        self.cipher = Fernet(self.secret.current)
        p = mock.patch.object(
            SessionTracker, "get_cipher", return_value=self.cipher
        )
        p.start()
        self.addCleanup(p.stop)


    def test_create_new_on_unparsable_cookie(self):
        with mock.patch.object(SessionTracker, "deserialize") as deserialize:
            with mock.patch.object(SessionTracker, "create") as create:
                deserialize.side_effect = UnparseableTokenError

                session_tracker_cookie = "this value is not used"
                SessionTracker.load(self.secret, session_tracker_cookie)

                create.assertCalledOnce()

    def test_create_new_on_corrupt_cookie(self):
        with mock.patch.object(SessionTracker, "deserialize") as deserialize:
            with mock.patch.object(SessionTracker, "create") as create:
                deserialize.side_effect = CorruptTokenError(
                    "msg", "id", "version", "created")

                session_tracker_cookie = "this value is not used"
                SessionTracker.load(self.secret, session_tracker_cookie)

                create.assertCalledOnce()

    def test_create_new_on_invalid_cookie(self):
        with mock.patch.object(SessionTracker, "deserialize") as deserialize:
            with mock.patch.object(SessionTracker, "create") as create:
                deserialize.side_effect = InvalidTokenError(
                    "msg", "id", "version", "created", "id", "version", "created")

                session_tracker_cookie = "this value is not used"
                SessionTracker.load(self.secret, session_tracker_cookie)

                create.assertCalledOnce()

    def test_accept_valid_cookie(self):
        FRESH_SESSION = mock.MagicMock(is_expired=False)
        with mock.patch.object(SessionTracker, "renew") as renew:
            with mock.patch.object(SessionTracker, "create") as create:
                with mock.patch.object(
                    SessionTracker, "from_str",
                    return_value=FRESH_SESSION,
                ) as from_str:

                    session_tracker_cookie = "this value is not used"
                    SessionTracker.load(self.secret, session_tracker_cookie)

                    from_str.assertCalledOnce()
                    create.assertNotCalled()
                    renew.assertCalledOnce()

    def test_create_new_on_expired(self):
        EXPIRED_SESSION = mock.MagicMock(is_expired=True)
        with mock.patch.object(SessionTracker, "create") as create:
            with mock.patch.object(
                SessionTracker, "from_str",
                return_value=EXPIRED_SESSION,
            ) as from_str:

                session_tracker_cookie = "this value is not used"
                SessionTracker.load(self.secret, session_tracker_cookie)

                from_str.assertCalledOnce()
                create.assertCalledOnce()
