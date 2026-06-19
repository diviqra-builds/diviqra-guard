# MIT License — Copyright (c) 2026 Diviqra


class GuardError(Exception):
    pass


class GuardBlockedError(GuardError):
    """Raised when Guard blocks a request or response."""
    pass


class GuardTimeoutError(GuardError):
    """Raised when the Guard service does not respond in time."""
    pass


class GuardConnectionError(GuardError):
    """Raised when the Guard service cannot be reached."""
    pass
