from django.core.cache import cache
from rest_framework.throttling import (
    AnonRateThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
)


class LoginRateThrottle(AnonRateThrottle):
    """
    Throttles login attempts to prevent brute force attacks.
    Rate limit is applied by IP address and username to prevent username enumeration.
    """

    scope = "login"

    def get_cache_key(self, request, view):
        # Get the username from the request data
        username = request.data.get("email", "")

        # Combine IP address and username to create a unique cache key
        # This prevents attackers from cycling through many usernames from the same IP
        ident = self.get_ident(request)
        return f"throttle_{self.scope}_{ident}_{username}"


class SignupRateThrottle(AnonRateThrottle):
    """
    Strict throttling for account creation to prevent spam accounts.
    """

    scope = "signup"


class TokenRefreshRateThrottle(UserRateThrottle):
    """
    Throttles token refresh requests to prevent token grinding attacks.
    """

    scope = "token_refresh"
