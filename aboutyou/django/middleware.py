#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""
import django.core.exceptions

try:
    from django.contrib.auth import authenticate, login
except django.core.exceptions.ImproperlyConfigured:
    pass

import logging


logger = logging.getLogger("aboutyou.middleware")


class AboutyouMiddleware(object):
    """
    An authentication middleware which uses aboutyou access token.

    This class uses the access token in the Authorization header or
    the *aboutyou_access_token* cookie for authentication.

    .. rubric:: Usage

    Add the class in **settings.py** to the middleware classes.

    .. code-block:: python

        MIDDLEWARE_CLASSES = (
            ...
            'aboutyou.django.middleware.AboutyouMiddleware',
        )
    """
    def process_request(self, request):
        try:
            if not request.user.is_authenticated():
                token = None

                # try to use the Authorization header
                if "HTTP_AUTHORIZATION" in request.META:
                    token = request.META["HTTP_AUTHORIZATION"].split(' ')[1]
                    logger.debug('got Authorization Header token: %s', token)
                else:

                    # there is no authorization header so we look in the cookies
                    if "aboutyou_access_token" in request.COOKIES:
                        token = request.COOKIES["aboutyou_access_token"]
                        logger.debug('got request cookie token: %s', token)

                if token:
                    user = authenticate(aboutyou_token=token)

                    if user is not None and not user.is_anonymous():
                        login(request, user)
        except Exception:
            logger.exception('')
