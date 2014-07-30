#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""
from aboutyou.shop import ShopApi
from aboutyou.config import JSONConfig

shop = ShopApi(JSONConfig('myconfig.json'))

# all categories of the first level
for category in shop.categories():
    print '---', category.name, '---'
    for sub in category:
        print sub.name

damen = shop.category_by_name("Damen")

print damen.id, damen.name
