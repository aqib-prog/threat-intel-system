"""Cross-cutting security controls for the API: rate limiting, response
headers, sanitized error handling, and API key authentication.

Kept separate from `api/` so security posture can be reviewed, tested, and
changed independently of endpoint/business logic.
"""

from security.rate_limit import limiter
from security.headers import SecurityHeadersMiddleware
from security.errors import log_and_sanitize
from security.auth import AUTH_ENABLED, is_auth_misconfigured, require_api_key

__all__ = [
    "limiter",
    "SecurityHeadersMiddleware",
    "log_and_sanitize",
    "AUTH_ENABLED",
    "is_auth_misconfigured",
    "require_api_key",
]
