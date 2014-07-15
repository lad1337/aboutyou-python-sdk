#-*- encoding: utf-8 -*-
"""
:Author:    Arne Simon [arne.simon@slice-dice.de]

+ https://github.com/aboutyou/php-jws/blob/master/src/Collins/Sign/JWS/SignService.php
+ https://github.com/ritou/php-Akita_JOSE/blob/master/src/Akita/JOSE/JWT.php
+ https://github.com/ritou/php-Akita_JOSE/blob/master/src/Akita/JOSE/Base64.php
"""
import base64
import hashlib
import hmac
import json
import os
import urllib
import urllib2
import uuid
import requests

from .config import Config


class AuthException(Exception):
    pass


signing_methods = {
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest(),
    'RS256': lambda msg, key: key.sign(hashlib.sha256(msg).digest(), 'sha256'),
    'RS384': lambda msg, key: key.sign(hashlib.sha384(msg).digest(), 'sha384'),
    'RS512': lambda msg, key: key.sign(hashlib.sha512(msg).digest(), 'sha512'),
    'none': lambda msg, key: '',
}


def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    input = input.replace('-', '+').replace('_', '/')
    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).rstrip('=').replace('+', '-').replace('/', '_')


def encode_state(state):
    return base64.b64encode(json.dumps(state))


def decode_state(value):
    return json.loads(base64.b64decode(value))


def orm_token(salt, secret, info, length=32, algorithm='HS256'):
    prk = signing_methods[algorithm](secret, salt)

    t = ''
    last_block = ''
    block_index = 1
    while len(t) < length:
        last_block = signing_methods[algorithm](last_block + info + chr(block_index), prk)
        t += last_block
        block_index += 1

    return t[:length]


def encode_payload(payload, secret, salt, algorithm='HS256'):
    segments = []
    header = {"typ": "JWS", "alg": algorithm}

    okm = orm_token(salt, secret, payload['info'], algorithm=algorithm)

    segments.append(base64url_encode(json.dumps(header, separators=(',', ':'))))
    segments.append(base64url_encode(json.dumps(payload, separators=(',', ':'))))
    signing_input = '.'.join(segments)

    signature = signing_methods[algorithm](signing_input, okm)

    segments.append(base64url_encode(signature))
    return '.'.join(segments)


def request_access_token(app_id, app_token, grant_code, redirect_uri, request_uri):
    headers = {
        'Authentication': 'Basic {}:{}'.format(app_id, app_token)
    }

    params = {
        'client_id': app_id,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
        'code': grant_code
    }

    result = requests.get(request_uri + '/oauth/token', params=params, headers=headers, verify=False)

    if result.status_code == 200:
        return result.json()
    else:
        raise AuthException(result.content)


class Auth(object):

    """
    This class wraps the Api user authorization interface.

    :param credentials: The app credentials.
    :param config: The app configuration.
    """

    def __init__(self, credentials, config=Config()):
        self.credentials = credentials
        self.config = config
        self.states = {}

    def login_url(self, redirect, scope='firstname', popup=False):
        """
        Returns this the url which provieds a user login.
        """
        # http://stackoverflow.com/questions/1293741/why-is-md5ing-a-uuid-not-a-good-idea
        uniqid = uuid.uuid4()
        self.states["csrf"] = hashlib.md5(uniqid.hex).hexdigest()

        payload = {
            "app_id": int(self.credentials.app_id),
            "info": "python_auth_sdk_{}".format(self.credentials.app_id),
            "redirect_uri": redirect,
            "scope": 'firstname',
            "popup": popup,
            'response_type': 'code',
            "state": encode_state(self.states),
            "flow": "auth"
        }

        salt = os.urandom(16)  # 16 bytes of randomnes
        payload["salt"] = base64.b64encode(salt)

        sign = encode_payload(payload, self.credentials.app_secret, salt, 'HS256')

        return self.config.shop_url + "?app_id=" + self.credentials.app_id + "&asr=" + sign

    def access_token(self, grant_code, redirect_uri):
        """
        :param grant_code: The grant code from the client.
        :param redirect_uri: The exact same redirect uri used in the login url.

        .. rubric:: returns

        .. code-block:: json

            {
                "access_token": "Sf4hWetQPVWTJAwoT7Q3tQ0NvDISIX",
                "token_type": "Bearer",
                "refresh_token": "fjkTOJG94o7ilKthP8hnlSRgC9Ptca",
                "scope": "firstname"
            }
        """
        return request_access_token(self.credentials.app_id,
                                    self.credentials.app_token,
                                    grant_code,
                                    redirect_uri,
                                    self.config.resource_url)

    def get_me(self, access_token):
        """
        Returns the user information to the corresponding Api access token.

        :param access_token: The access token retreived from the login.
        :raises AuthException: If the reuqests results in an error.

        .. rubric:: returns

        .. code-block:: json

            {
                "id": 7387,
                "firstname": "Axel"
            }
        """
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "User-Agent": self.config.agent,
            "Authorization": "Bearer {}".format(access_token)
        }

        response = requests.get(self.config.resource_url + "/api/me",
                                headers=headers,
                                verify=False)

        if response.status_code == 200:
            return response.json()
        else:
            raise AuthException(response.content)
