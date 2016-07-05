from cornice import Service, resource

import logging
log = logging.getLogger(__name__)
from goatfs_api.models import (
        Extension,
        Route
        )

from goatfs_api.security import (
        ResourceFactory
        )

route = Service(name='route', path='/route/{id}/{resource_id}', description="Sequence and Targets of Route specified by id", permission="view", factory=ResourceFactory,
cors_policy = {'origins': ('*',), 'credentials': True})

@route.get()
def get_route(request):
    user = request.user
    log.debug('User in ROUTE-view: {0}'.format(user))
    route_id = int(request.matchdict['id'])
    route = request.dbsession.query(Route).filter(Route.id==route_id).one()
    return route.reprJSON()

@route.post()
def post_route(request):
    user = request.user
    log.debug('User in ROUTE-post')
    return 'asdf'

route_extension = Service(name='route_extension', path='/route/extension/{extension}', description="Sequence and Targets of Route specified by extension", permission="edit",
cors_policy = {'origins': ('*',), 'credentials': True})

@route_extension.get()
def get_route_extension(request):
    user = request.user
    log.debug('User in ROUTE-view: {0}'.format(user))
    extension = request.matchdict['extension']
    route_list = list()
    extension = request.dbsession.query(Extension).filter(Extension.extension == extension).one()
    routes=sum([route.reprJSON() for route in extension.routes],[])
    return routes



#class RouteResource(object):
#    def __init__(self, request):
#        self.request = request
#
#    def collection_get(self):
#        return {'stuff':'asdf'}
#
#    def get(self):
#        route_id = int(self.request.matchdict['id'])
#        log.debug('ROUTE ID in request:{0}'.format(route_id))
#        route = self.request.dbsession.query(Route).filter(Route.id==route_id).one()
#        return route.reprJSON()
#
#resource.add_view(RouteResource.get, renderer='json')
#route_resource = resource.add_resource(RouteResource, collection_path='/routes', path='/routes/{id}', cors_policy = {'origins': ('*',), 'credentials': True})

