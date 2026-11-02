"""
Shared SlowAPI limiter.

It lives in its own file so main.py and the routers can all import it without
a circular import.

NOTE: Counts are stored in memory, so they reset when the server restarts and
aren't shared across server processes. A production app would use shared
storage such as Redis.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

LOGIN_LIMIT = "5/minute"
CREATE_LIMIT = "20/minute"
LIST_LIMIT = "60/minute"

# Limits are counted per client IP address.
# headers_enabled adds Retry-After and X-RateLimit-* headers to responses.
limiter = Limiter(key_func=get_remote_address, headers_enabled=True)
