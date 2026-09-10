"""Shared slowapi Limiter instance.

Must be a single instance used both by `app.main` (registered on
`app.state.limiter` + the rate-limit-exceeded exception handler) and by
any router applying `@limiter.limit(...)` to a specific endpoint --
two separate Limiter() instances would track state independently and
the exception handler wouldn't recognize limits set by the other.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
