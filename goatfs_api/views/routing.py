from cornice import Service, resource

from goatfs_api.models import (
        Extension,
        Route,
        Sequence
        )

from goatfs_api.security import (
        ResourceFactory
        )

import logging
log = logging.getLogger(__name__)

route = Service(name='route', path='/route/{id}', description="Sequence and Targets of Route specified by id", permission="view", factory=ResourceFactory,
        cors_policy = {'origins': ('*.goatfs.org:3000',), 'credentials': True})

@route.get()
def get_route(request):
    user = request.user
    log.debug('User in ROUTE-view: {0}'.format(user))
    route_id = int(request.matchdict['id'])
    route = Route.get_route_by_id(request, route_id)
    log.debug('Route found {0}'.format(route.id))
    return route.reprJSON()

@route.post()
def post_route(request):
    user = request.user
    log.debug('User in ROUTE-post: {0}'.format(user.user_name))
    route_json = request.json_body
    log.debug(route_json)
    route = Route.get_route_by_id(request, route_json['id'])
    for sequence in route.sequences:
        request.dbsession.delete(sequence)

    for sequence_json in route_json['sequences']:
        sequence = Sequence.add_sequence_from_json(request, route.id, sequence_json)

    return {'Status':'OK'}
