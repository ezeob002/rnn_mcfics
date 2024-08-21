import attr

@attr.s
class GICSFailure(Exception):

    message = attr.ib(type=str, default="")
    pass

class GICSError(Exception):
    pass


class GICSRestartFailedError(GICSError):
    pass


class GICSTargetConnectionFailedError(GICSError):
    pass

class GICSOutOfAvailableSockets(GICSError):
    pass

class GICSPaused(GICSError):
    pass


class GICSTestCaseAborted(GICSError):
    pass


class GICSTargetConnectionReset(GICSError):
    pass


class GICSTargetRecvTimeout(GICSError):
    pass


@attr.s
class GICSTargetConnectionAborted(GICSError):
    """
    Raised on `errno.ECONNABORTED`.
    """
    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class GICSRpcError(GICSError):
    pass


class GICSRuntimeError(Exception):
    pass
