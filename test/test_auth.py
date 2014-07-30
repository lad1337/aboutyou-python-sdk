#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""

def test_login_url(auth):
    auth.login_url('http://place-to-go.de')


# def test_me(auth, monkeypatch):
    # data = {u'lastname': u'Wurst', u'email': u'arne.simon@slice-dice.de', u'firstname': u'Axel', u'id': 68696}

    # monkeypatch.setattr("aboutyou.api.Aboutyou.request", request)

    # auth.get_access_token('arne.simon@slice-dice.de', 'abcd1234', 'http://place-to-go.de')