class E3Error(Exception):
    """Base class for every error Engine 3 raises (E4 maps these to HTTP codes)."""

class InvalidInput(E3Error):        # -> 400
    pass

class InvalidFilterError(E3Error):  # -> 400 (empty or bad filter)
    pass

class RunNotFound(E3Error):         # -> 404
    pass

class AlertNotFound(E3Error):       # -> 404
    pass

class QueryTimeout(E3Error):        # -> 504
    pass
