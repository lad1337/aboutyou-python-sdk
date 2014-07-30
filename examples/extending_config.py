#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""
from aboutyou.config import Config
from pymongo import MongoClient


class MongoDBClass(Config):

    def __init__(self, dburl='mongodb://localhost:27017/'):
        self.client = MongoClient(dburl)
        self.db = self.client['test-database']
        super(type(self), self).__init__()

    def __getattr__(self, name):
        return self.db.config.find_one().get(name)