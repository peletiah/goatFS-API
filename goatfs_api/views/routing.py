from cornice import Service, resource

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

route = Service(name='route', path='/route/{id}', description="Sequence and Targets of Route specified by id", permission="view", factory=RouteResourceFactory,
        cors_policy = {'origins': ('*.goatfs.org:3000',), 'credentials': True})

@route.get()
def get_route(request):
    user = request.user
    log.debug('User in ROUTE-view: {0}'.format(user))
    route_id = int(request.matchdict['id'])
    route = Route.get_route_by_id(request, route_id)
    log.debug('Route found {0}'.format(route.id))
    group = Group.get_group_by_id(request, 3)
    extensions = [extension.reprJSON() for extension in group.extensions]
    route_json = route.reprJSON()
    route_json['availableExtensions'] = extensions
    applications = ApplicationCatalog.get_applications(request)
    application_catalog = [application.reprJSON() for application in applications]
    route_json['applicationCatalog'] = application_catalog 
    return route_json

@route.put()
def update_route(request):
    user = request.user
    log.debug('User in ROUTE-post: {0}'.format(user.user_name))
    route_json = request.json_body
    log.debug(route_json)
    route = Route.get_route_by_id(request, route_json['id'])

    for sequence_id in route_json['removedSequences']:
        Sequence.delete_by_id(request, sequence_id)

    for sequence_json in route_json['sequences']:
        sequence = Sequence.add_change_sequence_from_json(request, route, sequence_json)
        try:
            if sequence.action:
                request.dbsession.delete(sequence.action)
            action = Action.add_action_from_json(request, sequence, sequence_json)
        except Exception as e:
            log.debug('Error delete action {0} in sequence {1}, {2}'.format( \
                sequence.action.id, sequence.id, e))
            raise
        
    response = HTTPNoContent()

    #TODO: Return update sequences/actions with id's and all 
    #      so we can update our react-state

    return response 
