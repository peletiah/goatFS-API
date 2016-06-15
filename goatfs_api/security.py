import logging

from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import (
        Allow, 
        Deny,
        Everyone, 
        Authenticated,
        authenticated_userid,
        forget,
        remember,
        ALL_PERMISSIONS
        )

from pyramid.httpexceptions import HTTPBadRequest

from goatfs_api.models.db_model import (
    Resource
    )

from .lib.authentication import JWTnBasicAuthAuthenticationPolicy, get_user_from_unauthenticated_userid

log = logging.getLogger(__name__)

def includeme(config):
    settings = config.get_settings()
    authn_policy = JWTnBasicAuthAuthenticationPolicy.from_settings(settings)
    authz_policy = ACLAuthorizationPolicy()
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    # get a User-object from *claimed* user, "reify" caches the result
    config.add_request_method(get_user_from_unauthenticated_userid, 'user', reify=True)


def permission_to_pyramid_acls(permissions):
    # adapted from ziggurat_foundations.permissions.permission_to_pyramid_acls
    # using perm.user.user_name instead of perm.user.id (Same for group)
    acls = []
    for perm in permissions:
        if perm.type == 'user':
            acls.append((Allow, perm.user.user_name, perm.perm_name))
        elif perm.type == 'group':
            acls.append((Allow, 'g:%s' % perm.group.group_name, perm.perm_name))
    log.debug(acls)
    return acls


class RootFactory(object):
   def __init__(self, request):
        self.__acl__ = [
                (Allow, Authenticated, u'schwurbel'), 
                ]
        # general page factory - append custom non resource permissions
        # request.user object from cookbook recipie
        if request.user:
            # for most trivial implementation

            # for perm in request.user.permissions:
            #     self.__acl__.append((Allow, perm.user.id, perm.perm_name,))

            # or alternatively a better way that handles both user
            # and group inherited permissions via `permission_to_pyramid_acls`

            for outcome, perm_user, perm_name in permission_to_pyramid_acls(
                    request.user.permissions):
                log.debug('Appending {0},{1},{2} to ACL'.format(outcome, perm_user, perm_name))
                self.__acl__.append((outcome, perm_user, perm_name))

class ResourceFactory(object):
    def __init__(self, request):
        self.__acl__ = []
        rid = request.matchdict.get("resource_id")

        log.debug('JJJJJJJAAAAAAAAAAAAAAAAAAAAAAAA:{0}'.format(rid))
        if not rid:
            raise HTTPBadRequest()
        self.resource = Resource.by_resource_id(rid,db_session=request.dbsession)
        if not self.resource:
            raise HTTPNotFound()
        if self.resource and request.user:
            # append basic resource acl that gives all permissions to owner
            #self.__acl__ = self.resource.__acl__
            # append permissions that current user may have for this context resource
            permissions = self.resource.perms_for_user(request.user)
            for outcome, perm_user, perm_name in permission_to_pyramid_acls(
                    permissions):
                self.__acl__.append((outcome, perm_user, perm_name,))
