# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A Pyramid authentication plugin for JSON Web Tokens:

    http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

"""

import sys
import functools

import binascii
import base64


from datetime import datetime
from calendar import timegm

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy, IDebugLogger
from pyramid.security import Everyone, Authenticated
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.util import DottedNameResolver

from pyramid.compat import (
    bytes_,
    )

import jwt

from goatfs_api.lib.auth_utils import verify_jwt_access_cookie, normalize_request_object
import goatfs_api.lib.exceptions as exc

from goatfs_api.models import (
        User,
        Group
        )

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.threadlocal import get_current_registry
from datetime import datetime, timedelta

from passlib.hash import bcrypt
from goatfs_api.lib.crypto import hash_context


import logging
log = logging.getLogger(__name__)
log.setLevel('INFO')

def b64decode(v):
    return base64.b64decode(bytes_(v))

def get_user_from_unauthenticated_userid(request):
    """
    Returns a User-object from *claimed* userid
    Defined via config.add_request_method in main()
    http://docs.pylonsproject.org/projects/pyramid-cookbook/en/latest/auth/user_object.html
    """
    log.debug('request_get_user')
    userid = request.unauthenticated_userid
    log.debug('userid in request: {0}'.format(userid))
    if userid is not None:
        return User.get_user(userid, request)
    return None



def groupfinder(request, user_name, password):
    log.debug('groupfinder called with Login: {0}'.format(user_name))
    registry = get_current_registry()
    policy = registry.getUtility(IAuthenticationPolicy)
    user = request.user
    try:
        # test if JWT signature and CSRF-cookie exists and is valid
        policy._check_signature(request)
        policy._check_csrf(request)

    except (exc.MissingToken,
            exc.InvalidSignature,
            exc.MissingCSRFCookie, 
            exc.MissingCSRFHeader, 
            exc.CSRFDoubleSubmitMismatch, 
            exc.CSRFMismatch) as e:
        # no JWT was sent or there is a problem with the CSRF
        # test for Basic Auth instead
        log.debug(e)
        if user and user.verify_password(password, request):
            pass
        else:
            log.debug('Wrong Password')
            return None

    except exc.NoAuthorizationHeader as e:
        log.debug(e)
        return None

    if user and user.groups:
        group_list = ['g:%s' % g.group_name for g in user.groups]
        log.info('groupfinder found GROUPS: {0} for USER: {1}'.format(group_list, user_name))
        return group_list
    elif user:
        log.info('groupfinder found USER: {0}'.format(user))
        return [user.user_name]
    else:
        log.info('groupfinder found no authentication credentials')
        return []

@implementer(IAuthenticationPolicy)
class JWTnBasicAuthAuthenticationPolicy(CallbackAuthenticationPolicy):
    """Pyramid Authentication Policy implementing JWT Access Auth and
    HTTP standard Basic Authentication protocol.

    CallbackAuthenticationPolicy provides get_effective_principals

    This class provides an IAuthenticationPolicy implementation based on
    signed requests, using the JSON Web Token Authentication standard or
    user-credentials in the HTTP-authentication header.

    The plugin can be customized with the following arguments:

        * check:  a callable taking a userid and a Request object, and
                        returning a list of the groups that userid is a
                        member of.

        * master_secret:  a secret known only by the server, used for signing
                          JWT auth tokens in the default implementation.

        * private_key:  An RSA private_key
        * private_key_file: a file holding an RSA encoded (PEM/DER) key file.

        * public_key:  An RSA public_key
        * public_key_file: a file holding an RSA encoded (PEM/DER) key file.

        * algorithm:  The algorithm used to sign the key (defaults to HS256)

        * leeway:  The default leeway (as a datetime.timedelta). Defaults to
                   None

        * userid_in_claim: The claim that the userid can be found in.  Normally
                           this is the 'sub' claim of the JWT, but this can
                           be overridden here.  This is used in
                           authenticated_userid() and related functions.

        * scheme: The scheme name used in the ``Authorization`` header. JWT
          implementations vary in their use of ``JWT`` (our default) or
          ``Bearer``.

    The following configuration options are to DISABLE the verification options
    in the PyJWT decode function.  If the app configures this then it OUGHT to
    ensure that the claim is verified IN the application.

        * decode_options (these are passed to the __init__() = undefined OR {}
          with the following keys (these are the defaults):

            options = {
               'verify_signature': True,
               'verify_exp': True,
               'verify_nbf': True,
               'verify_iat': True,
               'verify_aud': True
            }

          i.e to switch off audience checking, pass 'verify_aud': True in
          decode_options.

          These are passed as the following as part of the ini options/settings

          jwtauth.disable_verify_signature = true (default false)
          jwtauth.disable_verify_exp = true (default false)
          jwtauth.disable_verify_nbf = true (default false)
          jwtauth.disable_verify_iat = true (default false)
          jwtauth.disable_verify_aud = true (default false)

          NOTE: they are reversed between the settings vs the __init__().

    The library takes either a master_secret or private_key/public_key pair.
    In the later case the algorithm must be an RS* version.
    """

    # The default value of master_secret is None, which will cause the library
    # to generate a fresh secret at application startup.
    master_secret = None
    
    debug = True

    def _log(self, msg, methodname, request):
        logger = request.registry.queryUtility(IDebugLogger)
        if logger:
            cls = self.__class__
            classname = cls.__module__ + '.' + cls.__name__
            methodname = classname + '.' + methodname
            logger.debug(methodname + ': ' + msg)

    def __init__(self,
                 check=None,
                 master_secret=None,
                 private_key=None,
                 private_key_file=None,
                 public_key=None,
                 public_key_file=None,
                 algorithm='HS256',
                 leeway=None,
                 userid_in_claim=None,
                 scheme='JWT',
                 decode_options=None):
        log.debug('Initializing JWTnBasicAuthAuthenticationPolicy with callback {0}!'.format(check))
        if check is not None:
            self.check = check
        if master_secret is not None:
            self.master_secret = master_secret
        self.private_key = private_key
        if private_key_file is not None:
            with open(private_key_file, 'r') as rsa_priv_file:
                self.private_key = rsa_priv_file.read()
        self.public_key = public_key
        if public_key_file is not None:
            with open(public_key_file, 'r') as rsa_pub_file:
                self.public_key = rsa_pub_file.read()
        self.algorithm = algorithm
        if leeway is not None:
            self.leeway = leeway
        else:
            self.leeway = 0
        if userid_in_claim is not None:
            self.userid_in_claim = userid_in_claim
        else:
            self.userid_in_claim = 'sub'
        self.scheme = scheme
        self.decode_options = decode_options

    @classmethod
    def from_settings(cls, settings={}, prefix="jwtauth.", **extra):
        """Construct a JWTAuthenticationPolicy from deployment settings.

        This is a helper function for loading a JWTAuthenticationPolicy from
        settings provided in the pyramid application registry.  It extracts
        settings with the given prefix, converts them to the appropriate type
        and passes them into the constructor.
        """
        # Grab out all the settings keys that start with our prefix.
        log.debug('Getting the settings!')
        jwtauth_settings = {}
        for name in settings:
            if not name.startswith(prefix):
                continue
            jwtauth_settings[name[len(prefix):]] = settings[name]
        # Update with any additional keyword arguments.
        jwtauth_settings.update(extra)
        # Pull out the expected keyword arguments.
        kwds = cls._parse_settings(jwtauth_settings)
        # Error out if there are unknown settings.
        for unknown_setting in jwtauth_settings:
            raise ValueError("unknown jwtauth setting: %s" % unknown_setting)
        # And finally we can finally create the object.
        return cls(**kwds)

    @classmethod
    def _parse_settings(cls, settings):
        """Parse settings for an instance of this class.

        This classmethod takes a dict of string settings and parses them into
        a dict of properly-typed keyword arguments, suitable for passing to
        the default constructor of this class.

        Implementations should remove each setting from the dict as it is
        processesed, so that any unsupported settings can be detected by the
        calling code.
        """
        log.debug('parsing the settings!')
        load_function = _load_function_from_settings
        # load_object = _load_object_from_settings
        kwds = {}
        kwds["check"] = load_function("check", settings)
        kwds["master_secret"] = settings.pop("master_secret", None)
        kwds["private_key"] = settings.pop("private_key", None)
        kwds["private_key_file"] = settings.pop("private_key_file", None)
        kwds["public_key"] = settings.pop("public_key", None)
        kwds["public_key_file"] = settings.pop("public_key_file", None)
        kwds["algorithm"] = settings.pop("algorithm", "HS256")
        kwds["leeway"] = settings.pop("leeway", 0)
        kwds["userid_in_claim"] = settings.pop("userid_in_claim", "sub")
        kwds["scheme"] = settings.pop("scheme", "JWT")
        disable_options = {
            'verify_signature': settings.pop("disable_verify_signature", None),
            'verify_exp': settings.pop("disable_verify_exp", None),
            'verify_nbf': settings.pop("disable_verify_nbf", None),
            'verify_iat': settings.pop("disable_verify_iat", None),
            'verify_aud': settings.pop("disable_verify_aud", None),
        }
        kwds["decode_options"] = {
            k: not v for k, v in disable_options.items()}
        return kwds

    @classmethod
    def make_token(self, request, expire=7):
        registry = get_current_registry()
        #fetch the current instance of JWTAuthenticationPolicy (@implementer in lib/authentication)
        policy = registry.getUtility(IAuthenticationPolicy)
        expire = datetime.utcnow()+timedelta(seconds=60)
        token = policy.encode_jwt(request, claims={'sub': user_name, 'exp': expire})
        return token

    @classmethod
    def verify_password(cls, user_name, password):
        user = request.user
        if bcrypt.verify(password, user.password):
            return True
        else:
            return False


    def _clean_principal(self, princid):
        if princid in (Authenticated, Everyone):
            princid = None
        return princid


    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for the given request.

        This method extracts the claimed userid from the request without
        checking its authenticity.  This means that the request signature
        is *not* checked when you call this method.  The groupfinder
        callback is also not called.

        Returns username
        
        CallbackAuthenticationPolicy.effective_principals() calls this
        function to set the effective_principals
        """
        log.debug('>>> request method: {0}, request path: {1}'.format(request.method,request.path))
        log.debug('Calling "unauthenticated_userid" (extract userid from request without checking its authenticity)')
        try:
            userid = self._get_credentials(request)[0]
            log.debug('userid from unauthenticated_userid: {0}'.format(userid))
            return userid
        except Exception as e:
            log.debug('_get_credentials failed, Error: {0}'.format(e))
            raise

    def remember(self, request, principal, **kw):
        """Get headers to remember to given principal identity.

        This is a no-op for this plugin; the client is supposed to remember
        its MAC credentials and use them for all requests.
        """
        return []

    def callback(self, userid, request):
        """Find the list of groups for the given userid.

        This method provides a default implementation of the "groupfinder
        callback" used by many pyramid authn policies to look up additional
        user data.  It can be overridden by passing a callable into the
        JWTAuthenticationPolicy constructor.

        The default implementation returns an empty list.
        """
        log.debug('JWTnBasicAuthAuthorizationPolicy.callback')
        try:
            credentials = self._get_credentials(request)
            userid, password = credentials
            return self.check(request, userid, password)
        except Exception as e:
            log.debug('callback failed with: {0}'.format(e))
            return None

    def decode_jwt(self, request, jwtauth_token,
                   leeway=None, verify=True, options=None):
        """Decode a JWTAuth token into its claims.

        This method deocdes the given JWT to provide the claims.  The JWT can
        fail if the token has expired (with appropriate leeway) or if the
        token won't validate due to the secret (key) being wrong.

        If the JWT doesn't verify then a number of Exceptions can be raised:
            DecodeError() - if the algorithm in the token isn't supported.
            DecodeError() - if the secret doesn't match (key, etc.)
            ExpiredSignature() - if the 'exp' claim has expired.

        If private_key/public key is set then the public_key will be used to
        decode the key.

        Note that the 'options' value is normally None, as this function is
        usually called via the (un)authenticated_userid() which is called by
        the framework.  Thus the decode 'options' are set as part of
        configuring the module through Pyramid settings.

        :param request: the Pyramid Request object
        :param jwtauth_token: the string (bString - Py3) - of the full token
                              to decode
        :param leeway: Integer - the number of seconds of leeway to pass to
                       jwt.decode()
        :param verify: Boolean - True to verify - passed to jwt.decode()
        :param options: set of options for what to verify.
        """
        log.debug('decode JWT')
        if leeway is None:
            leeway = self.leeway
        if self.public_key is not None:
            key = self.public_key
        else:
            key = self.master_secret
        _options = self.decode_options or {}
        if options:
            _options.update(options)
        if len(_options.keys()) == 0:
            _options = None
        claims = jwt.decode(jwtauth_token,
                            key=key,
                            leeway=leeway,
                            verify=verify,
                            options=_options)
        log.debug(claims)
        return claims

    def encode_jwt(self, claims, key=None, algorithm=None):
        """Encode a set of claims into a JWT token.

        This is just a proxy for jwt.encode() but uses the default
        master_secret that may have been set in configuring the library.

        If the private_key is set then self.private_key is used for the encode
        (assuming key = None!)  algorithm also has to be an RS* algorithm and
        if not set, then self.algorithm is used.
        """
        log.debug('encode JWT')
        if key is None:
            if self.private_key is not None:
                key = self.private_key
            else:
                key = self.master_secret
        if algorithm is None:
            algorithm = self.algorithm
        # fix for older version of PyJWT which doesn't covert all of the time
        # claims.  This won't be needed in the future.
        encode_claims = maybe_encode_time_claims(claims)

        jwtauth_token = jwt.encode(encode_claims, key=key, algorithm=algorithm)
        return jwtauth_token

    def _get_params(self, request):
        """Get the JWTAuth parameters from the given request.

        This method parses the Authorization header to get the JSON Web
        Token. If they seem sensible, we cache them in the request
        to avoid reparsing and return them as a dict.

        If the request contains no JWT Auth credentials, None is returned.
        """
        log.debug('Get Params')
        try:
            log.debug('jwtauth.params in request: {0}'.format(request.environ["jwtauth.params"]))
            return request.environ["jwtauth.params"]
        except KeyError:
            params = verify_jwt_access_cookie(request, None)
            log.debug('params from verify_jwt_access_cookie: {0}'.format(params))
            if params is not None:
                if params.get("scheme").upper() !=self.scheme:
                    params = None
            request.environ["jwtauth.params"] = params
            return params

    def _get_credentials(self, request):
        """Extract the JWTAuth claims from the request.

        This method extracts and returns the claimed userid from the JWTAuth
        data in the request, along with the corresonding request signing
        key.  It does *not* check the signature on the request.

        If there are no JWTAuth credentials in the request then None
        is returned.
        """
        log.debug('Calling "get_credentials"')
        # check if there's an Authorization header (Basic Auth)
        if request.headers.get('Authorization'):
            log.debug('Authorization Header found, calling self._get_credentials_basic_auth')
            return self._get_credentials_basic_auth(request)

        userid = request.environ.get("jwtauth.userid", False)
        log.debug('jwtauth.userid in request.environ {0}'.format(userid))
        if userid:
            return userid, None

        params = self._get_params(request)
        log.debug('Params from "_get_params": {0}'.format(params))
        if params is None:
            return None, None
        if 'token' not in params:
            log.debug('no token in params')
            return None, None
        # Now try to pull out the claims from the JWT - note it is unusable if
        # we get a decode error, but might be okay if we get a signature error
        # Thus we may have to call decode TWICE, once with verify=True to see
        # if we just get a jwt.ExpiredSignature or jwt.DecodeError and if so,
        # the second time with verify=False to try to get the claims (i.e. to
        # ignore the jwt.ExpiredSignature)  we store whether the signature is
        # okay in jwtauth.signature_is_valid environ on the request
        def _get_claims():
            try:
                log.debug('Checking the claims in the JWT Token')
                claims = self.decode_jwt(request, params['token'], verify=True)
                return claims, True
            except (jwt.DecodeError, jwt.ExpiredSignature) as e:
            
            #TODO: Do we send ExpiredSignature-Error to client?
                log.debug('get_credentials returned error {0}'.format(e))
                # try again with no verify
                try:
                    claims = self.decode_jwt(
                        request, params['token'], verify=False)
                    return claims, False
                except jwt.DecodeError:
                    # can't do anything with this.
                    return None, False

        claims, is_signature_valid = _get_claims()
        log.debug('Is JWT Signature valid? {0}'.format(is_signature_valid))
        if claims is None:
            return None, None
        # so we don't have to check it again.
        request.environ["jwtauth.claims"] = claims
        request.environ["jwtauth.signature_is_valid"] = is_signature_valid
        # Now extract the userid and None, as there's no password in a JWT
        if self.userid_in_claim in claims:
            request.environ["jwtauth.userid"] = claims[self.userid_in_claim]
            return claims[self.userid_in_claim], None
        return None, None

    def _get_credentials_basic_auth(self, request):
        """ Userid and password parsed from the ``Authorization`` request header."""
        log.debug('_get_credentials_basic_auth')
        authorization = request.headers.get('Authorization')
        if not authorization:
            raise exc.NoAuthorizationHeader('No Authorization Header')
        try:
            authmeth, auth = authorization.split(' ', 1)
        except ValueError: # not enough values to unpack
            raise ValueError('Auth Header malformed')
        
        if authmeth.lower() != 'basic':
            raise NotBasicAuth('Auth method is not "Basic Auth"')

        try:
            authbytes = b64decode(auth.strip())
        # can't decode
        except TypeError:
            raise TypeError('Can\'t decode Authorization')
        except binascii.Error:
            raise binascii.Error('Can\'t decode Authorization')

        # try utf-8 first, then latin-1; see discussion in
        # https://github.com/Pylons/pyramid/issues/898
        try:
            auth = authbytes.decode('utf-8')
        except UnicodeDecodeError:
            auth = authbytes.decode('latin-1')

        try:
            username, password = auth.split(':', 1)
        except ValueError: # not enough values to unpack
            return None
        log.debug('_get_credentials_basic auth returns username:{0}, password:{1}'.format(username, password))
        return username, password

    def get_claims(self, request):
        """Get the claims from the request - if they exist.

        Fetch the claims out of the token on the request, if it exists and is
        decodable.  Returns None if there are none or it couldn't be docoded.
        """
        log.debug('get_claims')
        userid = self.unauthenticated_userid(request)
        if userid is None:
            return None
        return request.environ.get("jwtauth.claims", None)

    def _check_signature(self, request):
        """See if the signature was valid

        It was already checked in _get_credentials() - this function just
        sees if it was valid.

        If the JWTAuth token id is invalid then HTTPUnauthorized
        will be raised.
        """
        log.debug('check signature')
        # See if we've already checked the signature on this request.
        # This is important because pyramid doesn't cache the results
        # of authenticating the request, but we mark the nonce as stale
        # after the first check.
        if request.environ.get("jwtauth.signature_is_valid", False):
            log.debug('signature is valid')
            return True
        # Grab the (hopefully cached) params from the request.
        params = self._get_params(request)
        if params is None:
            # No access_token in the request or it was malformed
            raise exc.MissingToken('No JWT token was found')
        # We know the JWT auth token's signature isn't valid:
        raise exc.InvalidSignature('Invalid JWT signature')


    def _check_csrf(self, request):
        """
        Check if we have received a valid CSRF
        double submit. There should be a CSRF-Token
        in the X-XSRF-Token request header and the
        same token in a XSRF-Cookie.
        This token is a SHA512-hashed string 
        consisting of 'userid:jwt_expire:csrf_secret'
        """
        log.debug('check csrf')

        # Fetch CSRF token from request header and cookie and
        # compare the values

        csrf_from_cookie = request.cookies.get('csrf')
        if csrf_from_cookie is None:
            raise exc.MissingCSRFCookie('Missing CSRF Cookie in request')
        
        try:
            csrf_from_request = request.headers['x-csrf-token']
        except:
            raise exc.MissingCSRFHeader('Missing CSRF Header in request')

        double_submit_match = (csrf_from_request == csrf_from_cookie)
        if double_submit_match == False:
            raise exc.CSRFDoubleSubmitMismatch('CSRF Tokens in request do not match, request: {0}, cookie: {1}'.format(csrf_from_request, csrf_from_cookie))
    
        # Submitted Double Submit CSRF-Tokens match, let's
        # check if the hashed token content matches
        # with the content it should contain

        # Getting variables from settings and JWT to compute
        # the required hash
        csrf_secret = request.registry.settings.csrf_secret
        claims = request.environ.get("jwtauth.claims", None)
        expire = claims['exp']

        # Compute the hash from "userid:expire:csrf_secret"
        csrf_to_match = '{0}:{1}:{2}'.format(request.user.user_name, \
                                        expire, csrf_secret)

        # Verify if the computed hash matches the one submitted 
        # in the request
        csrf_ok = hash_context.verify(csrf_to_match, csrf_from_cookie)
        if csrf_ok == False:
            raise exc.CSRFMismatch('CSRF Token in request does not match computed CSRF')


def maybe_encode_time_claims(claims):
    encode_claims = claims.copy()
    # convert datetime to a intDate value in known time-format claims
    for time_claim in ['exp', 'iat', 'nbf']:
        if isinstance(encode_claims.get(time_claim), datetime):
            encode_claims[time_claim] = (
                timegm(encode_claims[time_claim].utctimetuple()))
    return encode_claims


@normalize_request_object
def authenticate_request(request, claims, key, algorithm='HS256', scheme='JWT'):
    """Authenticate a webob style request with the appropriate JWT token

    This creates the auth token using the claims and the key to ensure that
    will be accepted by this library.  Obviously, normally, a client would be
    making the request - so this is just useful as a 'canonical' way of
    creating a Authorization header
    """
    log.debug('authenticate request')
    claims = maybe_encode_time_claims(claims)
    jwtauth_token = jwt.encode(claims, key=key, algorithm=algorithm)
    if sys.version_info >= (3, 0, 0):
        jwtauth_token = jwtauth_token.decode(encoding='UTF-8')
    params = dict()
    params['token'] = jwtauth_token
    # Serialize the parameters back into the authz header, and return it.
    # WebOb has logic to do this that's not perfect, but good enough for us.
    request.authorization = (scheme, params)
    return request.headers['Authorization']


def _load_function_from_settings(name, settings):
    """Load a plugin argument as a function created from the given settings.

    This function is a helper to load and possibly curry a callable argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name] and checks that it is a callable.  It then looks for args
    of the form settings[name_*] and curries them into the function as extra
    keyword argument before returning.
    """
    log.debug('load function from settings')
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    func = DottedNameResolver(None).resolve(dotted_name)
    # Check that it's a callable.
    if not callable(func):
        raise ValueError("Argument %r must be callable" % (name,))
    # Curry in any keyword arguments.
    func_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            func_kwds[key[len(prefix):]] = settings.pop(key)
    # Return the original function if not currying anything.
    # This is both more efficent and better for unit testing.
    if func_kwds:
        func = functools.partial(func, **func_kwds)
    return func


def _load_object_from_settings(name, settings):
    """Load a plugin argument as an object created from the given settings.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name].  If this is a callable, it looks for arguments of the
    form settings[name_*] and calls it with them to instanciate an object.
    """
    log.debug('load object from settings')
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    obj = DottedNameResolver(None).resolve(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = settings.pop(key)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj


def includeme(config):
    """Install JWTAuthenticationPolicy into the provided configurator.

    This function provides an easy way to install JWT Access Authentication
    into your pyramid application.  Loads a JWTAuthenticationPolicy from the
    deployment settings and installs it into the configurator.
    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set before adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    log.debug('setting AUTH-policy')
    config.set_authorization_policy(authz_policy)

    # Build a JWTAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = JWTAuthenticationPolicy.from_settings(settings)
    log.debug(authn_policy)
    config.set_authentication_policy(authn_policy)
    log.debug('setting AUTH-policy')

    # Set the forbidden view to use the challenge() method on the policy.
    # The following causes a problem with cornice (fighting - open to options
    # about them playing properly together.)
    # config.add_forbidden_view(authn_policy.challenge)
