from cornice.resource import resource, view

from pyramid.httpexceptions import (
    HTTPCreated,
    HTTPNoContent
    )

from goatfs_api.models import (
        Extension,
        Group,
        Route,
        Sequence,
        Action,
        ActionApplication,
        ApplicationCatalog
        )

from goatfs_api.security import (
        RouteResourceFactory
        )

import logging
log = logging.getLogger(__name__)

                    
cors_policy = {'origins': ('*.goatfs.org:*','*.goatfs.org:3000'), 'credentials': True}

@resource(collection_path='/routes/', 
             path='/route/{id}', 
             description="Sequence and Targets of Route specified by id",
             permission="view", 
             factory=RouteResourceFactory,
             cors_policy = cors_policy
         )
class RouteResource(object):

    def __init__(self, request, context):
        self.request = request
        self.context = context
     

    @view(renderer='json')    
    def collection_get(self):
        user = self.request.user
        log.debug('User in ROUTES-view: {0}'.format(user))
        routes = Route.get_routes(self.request)
        routes_json = list()
        for route in routes:
            routes_json.append(route.reprJSON())
        log.debug(routes_json)
        return routes_json
    
    @view(renderer='json')    
    def get(self):
        user = self.request.user
        log.debug('User in ROUTE-view: {0}'.format(user))
        route_id = int(self.request.matchdict['id'])
        route = Route.get_route_by_id(self.request, route_id)
        log.debug('Route found {0}'.format(route.id))
        #TODO group_id depends on domain
        group = Group.get_group_by_id(self.request, 3)
        extensions = [extension.reprJSON() for extension in group.extensions]
        route_json = route.reprJSON()
        route_json['availableExtensions'] = extensions
        applications = ApplicationCatalog.get_applications(self.request)
        application_catalog = [application.reprJSON() for application in applications]
        route_json['applicationCatalog'] = application_catalog 
        return route_json
    
    @view(renderer='json')    
    def put(self):
        user = self.request.user
        log.debug('User in ROUTE-post: {0}'.format(user.user_name))
        route_json = self.request.json_body
        log.debug(route_json)
        route = Route.get_route_by_id(self.request, route_json['id'])
        if route.sequences:
            # delete all old sequences
            for sequence in route.sequences:
                self.request.dbsession.delete(sequence)
    
        # create fresh sequences based on JSON from client
        sequences = list()
        for sequence_json in route_json['sequences']:
            sequence = Sequence.add_sequence_from_json(self.request, route, sequence_json)
            try:
                if sequence.action:
                    self.request.dbsession.delete(sequence.action)
                action = Action.add_action_from_json(self.request, sequence, sequence_json)
            except Exception as e:
                log.debug('Error delete action {0} in sequence {1}, {2}'.format( \
                    sequence.action.id, sequence.id, e))
                raise
            sequences.append(sequence.createJSON(action))
        return route.createJSON(sequences)


#route_resource = resource.add_resource(RouteResource, 
#                    collection_path='/routes/', 
#                    path='/route/{id}', 
#                    description="Sequence and Targets of Route specified by id",
#                    permission="view", 
#                    factory=RouteResourceFactory,
#                    cors_policy = {'origins': ('*.goatfs.org:*','*.goatfs.org:3000'), 'credentials': True}
#                )

