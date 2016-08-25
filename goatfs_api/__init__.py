from pyramid.config import Configurator

import logging
log = logging.getLogger(__name__)


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings,
                root_factory='.security.RootFactory')
    config.include('pyramid_mako')
    config.include('.models')
    config.include('.routes')
    config.include('cornice')
    config.include('.security')
    config.scan()
    return config.make_wsgi_app()
