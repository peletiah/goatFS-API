from cornice import Service, resource

import logging
log = logging.getLogger(__name__)
from goatfs_api.models import (
        Extension,
        Route,
        Sequence
        )

from goatfs_api.security import (
        ResourceFactory
        )

dialplan = Service(name='dialplan', path='/dialplan', description="XML Dialplan for Extension",
        renderer='dialplan.mako', content_type='text/xml',
        permission="edit", factory=ResourceFactory, cors_policy = {'origins': ('*.goatfs.org:3000',), 'credentials': True})

@dialplan.get()
def get_dialplan(request):
    user = request.user
    log.debug('User in DIALPLAN-get: {0}'.format(user))
    #log.debug('REQUEST PATH QUERYSTRING {0}'.format(request.path_qs))
    log.debug('REQUEST PARAMS {0}'.format(request.params.getall('hostname')))
    destination_number = request.params.getone('Caller-Destination-Number')
    extension = request.dbsession.query(Extension).filter(Extension.extension == destination_number).one()
    route = request.dbsession.query(Route).filter(Route.extension_id == extension.id).first()
    log.debug(route.reprJSON())
    return {
            'extension': extension.extension,
            'route': route
            }

    
