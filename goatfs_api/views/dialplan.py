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

dialplan = Service(name='dialplan', path='/dialplan/{extension}', description="XML Dialplan for Extension", 
        permission="edit", factory=ResourceFactory, cors_policy = {'origins': ('*',), 'credentials': True})

@dialplan.get()
def get_dialplan(request):
    user = request.user
    log.debug('User in DIALPLAN-get: {0}'.format(user))
    extension = request.matchdict['extension']
    extension = request.dbsession.query(Extension).filter(Extension.extension == extension).one()
    log.debug(extension.extension)
    return extension.extension

    
