class APIError(Exception):
    """This exception gets raised whenever a non-200 status code was returned by the Shodan API."""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        # Make sure the exception can always be printed, even if the API
        # returned a non-string value for the error message.
        return str(self.value)


class APITimeout(APIError):
    pass
