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
    def authenticate(self, access_token=None):
        """
        :param access_token: The aboutyou access token.
        """
        user = None

        try:
            data = settings.AUTH.get_me(access_token)

            if data:
                user, created = get_user_model().objects.get_or_create(aboutyou_id=data.get("id"))

                firstname = data.get("firstname")

                if firstname:
                    user.first_name = firstname

                if created and firstname:
                    user.username = firstname

                    logger.info("created user %s %s", user.aboutyou_id, user.username)

                user.save()

        except Exception:
            logger.exception('access_token: {}'.format(grant_code))
            user = None

        if user is not None:
            logger.debug("authenticated user %s %s %s", user.id, user.aboutyou_id, user.username)

            return user


