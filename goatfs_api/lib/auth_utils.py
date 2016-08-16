# utils for pyramid_jwtauth

# This code heavily borrowed from:
# https://github.com/mozilla-services/macauthlib

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Low-level utility functions for pyramid_jwtauth

"""

import re
import functools

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.threadlocal import get_current_registry
from datetime import datetime, timedelta
from goatfs_api.lib.crypto import hash_context

import logging
log = logging.getLogger(__name__)
log.setLevel('INFO')

# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = re.compile(r'^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$')

# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")


def verify_jwt_access_cookie(request, *default):
    """Parse the JWT token and return a dict
    """
    # This outer try-except catches ValueError and
    # turns it into return-default if necessary.
    log.debug('parse_jwt_access_cookie')
    try:
        # Grab the access_token from the cookie in the request, if any.
        token = request.cookies.get('access_token')
        log.debug('JWT token is {0}'.format(token))
        if token is None:
            raise ValueError("Missing auth parameters")
        # remove backslash
        token = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], token)
        if not _AUTH_PARAM_RE.match(token):
            raise ValueError('Malformed auth parameters')
        params = {"scheme": 'JWT'}
        if _UNESC_QUOTE_RE.search(token):
            raise ValueError("Unescaped quote in quoted-string")
        params['token'] = token
        return params
    except ValueError as e:
        log.debug('ValueError in parse_jwt_access_cookie: {0}'.format(e))
        if default:
            return default[0]


def parse_authz_header(request, *default):
    """Parse the authorization header into an identity dict.
    This function can be used to extract the Authorization header from a
    request and parse it into a dict of its constituent parameters.  The
    auth scheme name will be included under the key "scheme", and any other
    auth params will appear as keys in the dictionary.
    For example, given the following auth header value:
        'Digest realm="Sync" userame=user1 response="123456"'
    This function will return the following dict:
        {"scheme": "Digest", realm: "Sync",
         "username": "user1", "response": "123456"}
    """
    # This outer try-except catches ValueError and
    # turns it into return-default if necessary.
    try:
        # Grab the auth header from the request, if any.
        authz = request.environ.get("HTTP_AUTHORIZATION")
        if authz is None:
            raise ValueError("Missing auth parameters")
        scheme, kvpairs_str = authz.split(None, 1)
        # Split the parameters string into individual key=value pairs.
        # In the simple case we can just split by commas to get each pair.
        # Unfortunately this will break if one of the values contains a comma.
        # So if we find a component that isn't a well-formed key=value pair,
        # then we stitch bits back onto the end of it until it is.
        kvpairs = []
        if kvpairs_str:
            for kvpair in kvpairs_str.split(","):
                if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                    kvpairs.append(kvpair)
                else:
                    kvpairs[-1] = kvpairs[-1] + "," + kvpair
            if not _AUTH_PARAM_RE.match(kvpairs[-1]):
                raise ValueError('Malformed auth parameters')
        # Now we can just split by the equal-sign to get each key and value.
        params = {"scheme": scheme}
        for kvpair in kvpairs:
            (key, value) = kvpair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if _UNESC_QUOTE_RE.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
            params[key] = value
        return params
    except ValueError:
        if default:
            return default[0]
        raise

def normalize_request_object(func):
    """Decorator to normalize request into a WebOb request object.
    This decorator can be applied to any function taking a request object
    as its first argument, and will transparently convert other types of
    request object into a webob.Request instance.  Currently supported
    types for the request object are:
        * webob.Request objects
        * requests.Request objects
        * WSGI environ dicts
        * bytestrings containing request data
        * file-like objects containing request data
    If the input request object is mutable, then any changes that the wrapped
    function makes to the request headers will be written back to it at exit.
    """
    @functools.wraps(func)
    def wrapped_func(request, *args, **kwds):
        orig_request = request
        # Convert the incoming request object into a webob.Request.
        if isinstance(orig_request, webob.Request):
            pass
        # A requests.PreparedRequest object?
        elif requests and isinstance(orig_request, requests.PreparedRequest):
            # Copy over only the details needed for the signature.
            # WebOb doesn't code well with bytes header names,
            # so we have to be a little careful.
            request = webob.Request.blank(orig_request.url)
            request.method = orig_request.method
            for k, v in iteritems(orig_request.headers):
                if not isinstance(k, str):
                    k = k.decode('ascii')
                request.headers[k] = v
        # A WSGI environ dict?
        elif isinstance(orig_request, dict):
            request = webob.Request(orig_request)
        # A bytestring?
        elif isinstance(orig_request, bytes):
            request = webob.Request.from_bytes(orig_request)
        # A file-like object?
        elif all(hasattr(orig_request, attr) for attr in ("read", "readline")):
            request = webob.Request.from_file(orig_request)

        # The wrapped function might modify headers.
        # Write them back if the original request object is mutable.
        try:
            return func(request, *args, **kwds)
        finally:
            if requests and isinstance(orig_request, requests.PreparedRequest):
                orig_request.headers.update(request.headers)

    return wrapped_func

def make_jwt(login, expire=7):
    registry = get_current_registry()
    #fetch the current instance of JWTAuthenticationPolicy (@implementer in lib/authentication)
    policy = registry.getUtility(IAuthenticationPolicy)
    expire = datetime.utcnow()+timedelta(days=expire)
    token = policy.encode_jwt(claims={'sub': login, 'exp': expire})
    return token



def make_csrf(request, login, jwt):
    csrf_secret = request.registry.settings.csrf_secret
    registry = get_current_registry()
    policy = registry.getUtility(IAuthenticationPolicy)
    claims=policy.decode_jwt(request, jwt)
    expire = claims['exp']
    csrf_token = hash_context.encrypt('{0}:{1}:{2}'.format(login, expire, csrf_secret))
    return csrf_token
