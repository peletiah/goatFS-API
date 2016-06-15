from pyramid.response import Response
from pyramid.view import view_config, forbidden_view_config

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPNotFound, HTTPFound, HTTPUnauthorized
from pyramid.security import forget

from sqlalchemy.exc import DBAPIError
from datetime import datetime, timedelta

from pyramid.httpexceptions import HTTPNoContent

#from auth.lib.jwt_auth import JWTAuthenticationPolicy as jwt_auth_policy

from cornice import Service
from cornice.validators import DEFAULT_FILTERS
from goatfs_api.lib.exceptions import _204, _401
import goatfs_api.lib.auth_utils as auth_utils

import json

import logging
log = logging.getLogger(__name__)

from goatfs_api.models.db_model import (
        User,
        AuthToken
        )

@forbidden_view_config()
def challenge(request):
    return _401.auth_jwt_basic()



desc = """
Resource /sign_in
Accepts PUT with JSON encoded login and password
Returns a cookie with a JWT

Allowed methods:
- PUT
"""

sign_in = Service(name='sign_in', path='/sign_in', description='Sign In',
cors_policy= {'origins': ('*',), 'credentials': True})

@sign_in.put()
def signin(request):
    """Content-Type: application/json \ 
    Properties : \
    - login (String)\
    - password (String)\
    """
    log.debug(request.json_body)
    login = request.json_body['login']
    password = request.json_body['password']
    log.debug('Login attempt as {0}'.format(login))
    log.debug('Login attempt with password {0}'.format(password))
    
    if login and password:

        user = User.get_user(login, request)

        if user and user.verify_password(password, request):
            jwt = auth_utils.make_jwt(login, expire=7)
            csrf = auth_utils.make_csrf(request, login, jwt)
            log.debug('JWT: {0}, CSRF: {1}'.format(jwt,csrf))
            return _204.with_cookies(jwt, csrf)

        else:
            log.debug('LOGIN FAILED with {0} and {1}'.format(login,password))
            return _401.auth_jwt()
    else:
        return _401.auth_jwt_basic()


@view_config(route_name='logout')
def logout(request):
    #TODO for JWT Tokens, we could add an iat-claim 
    # and track tokens in a table with their expiry-date
    # making it possible to revoke them on user-delete (and auto-remove after expiry)
    return response


