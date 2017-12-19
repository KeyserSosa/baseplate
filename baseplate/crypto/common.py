from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hmac
from datetime import datetime

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
