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


def encode(payload, secret, salt, algorithm='HS256'):
    segments = []
    header = {"typ": "JWS", "alg": algorithm}

    okm = orm_token(salt, secret, payload['info'], algorithm=algorithm)

    segments.append(base64url_encode(json.dumps(header, separators=(',', ':'))))
    segments.append(base64url_encode(json.dumps(payload, separators=(',', ':'))))
    signing_input = '.'.join(segments)

    signature = signing_methods[algorithm](signing_input, okm)

    segments.append(base64url_encode(signature))
    return '.'.join(segments)


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

    def old_login_url(self, redirect):
        """
        Generates the login url.

        :param appid: The app id for which context the user will should generate an access token.
        :param redirect: An url to which the browser will be redirected after login.

        .. note::

            Besure that the redirect url is registered in the devcenter!
        """
        url = self.config.shop_url + "?client_id="
        url += str(self.credentials.app_id) + "&redirect_uri="
        url += redirect + "&response_type=token&scope=firstname+id"

        return url

    def __buildStateUrlValue(self):
        return base64.b64encode(json.dumps(self.states))

    def __parseStateUrlValue(self, value):
        return json.loads(base64.b64decode(value))

    def __sign(self, payload):
        salt = os.urandom(16)  # 16 bytes of randomnes
        payload["salt"] = base64.b64encode(salt)

        sign = encode(payload, self.credentials.app_secret, salt, 'HS256')

        return sign

    def login_url(self, redirect, scope='firstname', popup=False):
        """
        Returns this the url which provieds a user login.
        """
        # http://stackoverflow.com/questions/1293741/why-is-md5ing-a-uuid-not-a-good-idea
        uniqid = uuid.uuid4()
        self.states["csrf"] = hashlib.md5(uniqid.hex).hexdigest()

        payload = {"app_id": int(self.credentials.app_id),
                   "info": "auth_sdk_{}".format(self.credentials.app_id),
                   "redirect_uri": redirect,
                   "scope": 'firstname',
                   "popup": popup,
                   'response_type': 'code',
                   "state": self.__buildStateUrlValue(),
                   "flow": "auth"}

        sign = self.__sign(payload)

        return self.config.shop_url + "?app_id=" + self.credentials.app_id + "&asr=" + sign

    def get_me(self, access_token):
        """
        Returns the user information to the corresponding Api access token.

        :param access_token: The access token retreived from the login.
        :raises AuthException: If the reuqests results in an error.
        """
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "User-Agent": self.config.agent,
            "Authorization": "Bearer {}".format(access_token)
        }

        response = requests.get("https://oauth.collins.kg/oauth/api/me",
                                headers=headers,
                                verify=False)

        if response.status_code == 200:
            return response.json()
        else:
            raise AuthException(response.content)

    def get_access_token(self, email, password, redirect):
        """
        A dirty hack to get an access token right away.

        This function fakes an webbrowser and a user which logins
        on the Api website.

        :param email: The email of an user.
        :param password: The corresponding password.
        :param redirect: The redirect url to use.
        :returns: <access_token>, <token_type>
        :raises AuthException: If an request error occours.
        """
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "User-Agent": "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36",
        }

        session = requests.Session()
        session.headers.update(headers)
        response = session.get(self.login_url(redirect), verify=False)

        if response.status_code != 200:
            raise AuthException(response.content)

        url = self.config.shop_url + 'login'
        data = {'LoginForm[email]': email, 'LoginForm[password]': password}
        params = {'avstdef': 2, 'client_id': 110, 'redirect_uri': redirect,
                  'scope': 'firstname+id+lastname+email', 'response_type': 'token'}
        response = session.post(url, data=data, params=params, verify=False)

        if response.status_code == 200:
            data = response.url.split('#')
            if len(data) == 2:

                values = dict((x.split('=') for x in data.split('&')))

                return values['access_token'], values['token_type']
            else:
                # print session.headers
                # print session.cookies
                # print response.headers
                # print response.cookies
                # with open(os.path.abspath('/home/gojira/dump.auth.html'), 'w') as out:
                #     out.write(response.content)
                raise AuthException('could not reteive token')
        else:
            raise AuthException(response.content)
