import pyramid.httpexceptions as exc
from jwt import InvalidTokenError

"""
HTTP Exceptions
"""

class _204(exc.HTTPNoContent):
    """ HTTP 204 No Content """

    @classmethod
    def with_cookies(cls, jwt, csrf):
        """ return 204 with JWT in a cookie"""
        response = cls()
        response.set_cookie(
                    'access_token',
                    jwt,
                    httponly=True,
                    overwrite=True,
                    domain='goatfs.org'
                    #max_age=20
                    )
        response.set_cookie(
                    'csrf',
                    csrf,
                    httponly=False,
                    overwrite=True,
                    domain='goatfs.org'
                    #max_age=20
                    )
 
        return response

class _401(exc.HTTPUnauthorized):
    """ HTTP 401 Unauthorized Response """

    @classmethod
    def auth_jwt(cls):
        """ add a JWT Authentication header """
        response = cls()
        response.headers.add('WWW-Authenticate','JWT')
        return response
    
    @classmethod
    def auth_jwt_basic(cls):
        """ add a JWT and 'HTTP Basic Auth' Authentication header """
        response = cls()
        response.headers.add('WWW-Authenticate','JWT')
        response.headers.add('WWW-Authenticate', 'Basic realm="Please log in"')
        return response

"""
Basic Auth Exceptions
"""

class NoAuthorizationHeader(Exception):
    pass

class NotBasicAuth(Exception):
    pass

"""
JWT Exceptions
"""

class MissingToken(InvalidTokenError):
    pass

class InvalidSignature(InvalidTokenError):
    pass


"""
CSRF Exceptions
"""

class MissingCSRFCookie(Exception):
    pass

class MissingCSRFHeader(Exception):
    pass

class CSRFDoubleSubmitMismatch(Exception):
    pass

class CSRFMismatch(Exception):
    pass

