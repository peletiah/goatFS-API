from cornice import Service

import logging
log = logging.getLogger(__name__)


from goatfs_api.models import (
        Domain,
        Menu
        )

menu = Service(name='menu', path='/menu', description="Return the menu for specific user and domain",
cors_policy = {'origins': ('*',), 'credentials': True})

@menu.get()
def get_menu(request):
    user = request.user
    log.debug('User in MENU-view: {0}'.format(user))
    #TODO: replace "1" with actual domain-id
    menu = Menu.get_menu(1, request).reprJSON()
    log.debug(menu)
    return menu
