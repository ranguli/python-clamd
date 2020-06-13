class ClamdError(Exception):
    pass


class ResponseError(ClamdError):
    pass


class BufferTooLongError(ResponseError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""

    pass


class ConnectionError(ClamdError):
    """Class for errors communication with clamd"""

    pass
