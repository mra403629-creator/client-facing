class GatewayError(Exception):
    status = 500


class Unauthorized(GatewayError):
    status = 401


class Forbidden(GatewayError):
    status = 403


class NotFound(GatewayError):
    status = 404


class Conflict(GatewayError):
    status = 409


class Invalid(GatewayError):
    status = 422


class RateLimited(GatewayError):
    status = 429


class Upstream(GatewayError):
    status = 502
