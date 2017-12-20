from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hmac
import math
from datetime import datetime, timedelta, tzinfo

if hasattr(hmac, "compare_digest"):
    # This was added in Python 2.7.7 and 3.3
    # pylint: disable=invalid-name,no-member
    constant_time_compare = hmac.compare_digest
else:
    def constant_time_compare(actual, expected):
        """Return whether or not two strings match.

        The time taken is dependent on the number of characters provided
        instead of the number of characters that match which makes this
        function resistant to timing attacks.

        """
        actual_len = len(actual)
        expected_len = len(expected)
        result = actual_len ^ expected_len
        if expected_len > 0:
            for i in xrange(actual_len):
                result |= ord(actual[i]) ^ ord(expected[i % expected_len])
        return result == 0


class UTC(tzinfo):
    """Implement the UTC timezone."""

    ZERO = timedelta(0)

    def utcoffset(self, dt):   # pylint: disable=unused-argument
        return self.ZERO

    def tzname(self, dt):   # pylint: disable=unused-argument
        return "UTC"

    def dst(self, dt):   # pylint: disable=unused-argument
        return self.ZERO


UTC = UTC()
EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=UTC)


def epoch_timestamp(dt):
    """Return the number of seconds from the epoch to date.

    :param datetime dt: datetime (with time zone)
    :rtype: float
    """
    return (dt - EPOCH).total_seconds()


def to_epoch_milliseconds(dt):
    """Return the number of milliseconds from the epoch to date.

    :param datetime dt: datetime (with time zone)
    :rtype: int
    """
    return int(math.floor(1000. * epoch_timestamp(dt)))


def from_epoch_milliseconds(ms):
    """Convert milliseconds from the epoch to UTC datetime.

    :param int ms: milliseconds since the epoch
    :rtype: :py:class:`datetime.datetime`
    """
    seconds = int(ms / 1000.)
    microseconds = (ms - 1000 * seconds) * 1000.
    return EPOCH + timedelta(seconds=seconds, microseconds=microseconds)
