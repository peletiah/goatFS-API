from pyramid.config import Configurator

from cornice import Service
from cornice.tests.support import CatchErrors

service = Service(name="service", path="/service")


def has_payed(request):
    if not 'paid' in request.GET:
        request.errors.add('body', 'paid', 'You must pay!')


@service.get(validators=has_payed)
def get1(request):
    return {"test": "succeeded"}
