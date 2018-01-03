from datetime import datetime, timedelta
import string
import random

from . token import EncryptedToken
from . common import UTC
from . errors import (
    CorruptTokenError,
    InvalidTokenError,
    UnparseableTokenError,
)


class SessionTracker(EncryptedToken):

    ID_LENGTH = 18
    CHARSPACE = string.ascii_uppercase + string.ascii_lowercase + string.digits
    MAX_AGE = timedelta(minutes=30)

    @classmethod
    def create(cls, secret):
        token_id = ''.join(
            random.choice(cls.CHARSPACE) for _ in xrange(cls.ID_LENGTH)
        )
        return cls(secret, token_id)

    def renew(self):
        self.created = datetime.now(UTC)

    @property
    def is_expired(self):
        age = datetime.now(UTC) - self.created
        return age > self.__class__.MAX_AGE

    @classmethod
    def load(cls, secret, token_str):
        """Load session from string or create a new one if needed.

        :rtype: :py:class:`SessionTracker`
        """
        session_tracker = None
        if token_str:
            session_tracker = cls.from_str(secret, token_str)
        if session_tracker and not session_tracker.is_expired:
            session_tracker.renew()
            return session_tracker
        else:
            return cls.create(secret)

    def to_event_payload(self):
        """Serialize SessionTracker for use in the event pipeline."""
        return self.to_dict(prefix="session")
