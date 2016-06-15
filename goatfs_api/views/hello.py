from cornice import Service

import logging
log = logging.getLogger(__name__)

_VALUES = {"content": "<p>Note: Right now we are in our tent at the far east end of Turkey, <a href=\"https://www.google.com/maps?q=38.63024,+44.19201&amp;hl=en&amp;ll=38.630282,44.307175&amp;spn=0.528352,1.056747&amp;sll=37.0625,-95.677068&amp;sspn=66.954931,135.263672&amp;t=p&amp;z=11\">between Saray and Kapikoy</a>. We are at 2100m and it\'s a freezing cold night under a carpet of stars.</p>\n<p>Tomorrow we will enter Iran.</p>\n<p>The last 3 weeks have been pretty taxing for us - eastern Turkey is even more hilly than the western and central parts of Anatolia i\'ve cycled in 2010 and our comfortable life in the last 2 years has had its impact on our physical condition and body fat. We managed to wind down a few kilometers each day, take a outdoor shower, get dinner made and crawl in our sleeping bags to fall asleep within minutes. So please bear with us for a few more updates on our travel so far - here\'s at least a first glimpse:</p>\n<p>[imgid222]</p>\n<p>&nbsp;</p>\n<p>&nbsp;Arriving in Malatya it was a joy to meet Illyas and Zeh\'ra again. When i met them the last time, Zeh\'ra was pregnant and Diran is now a sweet child of 2. Unfortunately i didn\'t get a shot of Zeh\'ra when we left, as she is busy finishing her studies(Besides managing a family).</p>\n<p>[imgid233]</p>\n<p>&nbsp;Getting out of Malatya on the D300 was as usual a dull experience on a arterial road with lots of trucks. It was however sweetened by two pretty good campsites and a excellent roadside locanta(Turkish buffet-restaurant) where i got to try&nbsp;<a href=\"http://en.wikipedia.org/wiki/Menemen_(food)\">Menemen</a>&nbsp;for the first time</p>\n<p>[imgid235]</p>\n<p>&nbsp;</p>\n<p>[imgid239]</p>\n<p>&nbsp;</p>\n<p>&nbsp;</p>", "uuid": "cbf10c09-71df-4623-96c0-367fff4cd8d0", "created": "2013-05-24 07:05:26", "author": "christian", "topic": "Malatya revisited", "tracks": [{"distance": "0.001", "reduced_trackpoints": "[[38.3094176, 38.336528], [38.3094208, 38.336528]]", "uuid": "08198f5a-7b2a-4cbd-afb7-af777a013ddf", "timespan": "0:00:40", "color": "FF0000", "start_time": "2013-05-22 13:27:49", "end_time": "2013-05-22 13:28:29", "published": None, "id": 43, "trackpoint_count": 5}]}


hello = Service(name='hello', path='/hello', description="Simplest app", permission="edit",
cors_policy = {'origins': ('*',), 'credentials': True})

@hello.get()
def get_info(request):
    user = request.user
    log.debug('User in HELLO-view: {0}'.format(user))
    """Returns Hello in JSON."""
    log.debug('Sending hello world')
    return _VALUES
