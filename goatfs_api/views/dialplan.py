from cornice import Service

import logging
log = logging.getLogger(__name__)

dialplan = Service(name='dialplan', path='/dialplan/{id}', description="Return dialplan by id", permission="edit",
cors_policy = {'origins': ('*',), 'credentials': True})

@dialplan.get()
def get_dialplan(request):
    user = request.user
    log.debug('User in HELLO-view: {0}'.format(user))
    return _DIALPLAN
