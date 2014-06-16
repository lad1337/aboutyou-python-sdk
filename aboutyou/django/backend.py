#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""
import django.core.exceptions

try:
    from django.conf import settings
    from django.contrib.auth.backends import ModelBackend
    from django.contrib.auth import get_user_model
except django.core.exceptions.ImproperlyConfigured:
    # Sphinx complains about improperly configured django project at build time
    # so we create a dummy ModelBackend class for proper docu creation.
    class ModelBackend:
        pass

import logging


logger = logging.getLogger("aboutyou.backend")


class AboutyouBackend(ModelBackend):
    """
    An aboutyou backend which authenticates a user by its access token.

    .. note::

        If no user with the corresponding aboutyou id exists a new one will be created.

    .. note::

        Your user model has to have a field **aboutyou_id**.

    .. rubric:: Usage

    .. code-block:: python

        AUTHENTICATION_BACKENDS = (
            'django.contrib.auth.backends.ModelBackend',
            'aboutyou.django.backend.AboutyouBackend',
        )
    """
    def authenticate(self, aboutyou_token=None):
        """
        :param aboutyou_token: The aboutyou access token.
        """
        if aboutyou_token is not None:

            data = settings.AUTH.get_me(aboutyou_token)

            if data:
                user = None

                try:
                    user, created = get_user_model().objects.get_or_create(aboutyou_id=data.get("id"))

                    # user.token = aboutyou_token
                    user.email = data.get("email")
                    user.first_name = data.get("firstname")
                    user.last_name = data.get("lastname")

                    if created:
                        user.username = "{}_{}.".format(data.get("firstname"), data.get("lastname")[0])

                        logger.info("created user %s %s %s", user.aboutyou_id, user.username, user.email)

                    user.save()

                except Exception:
                    logger.exception('aboutyou_token')
                    user = None

                if user is not None:
                    logger.debug("authenticated user %s %s %s", user.aboutyou_id, user.username, user.email)

                    return user


