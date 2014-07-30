#-*- coding: utf-8 -*-
"""
:Author: Arne Simon [arne.simon@slice-dice.de]
"""
from aboutyou.config import YAMLConfig
from aboutyou.shop import ShopApi

shop = ShopApi(YAMLCredentials('mycredentials.yml'))

basket = shop.basket(session)

products, with_errors = shop.productsById([434091])

product = products.get(434091)

if product:
    variant = product.variants[0]

    print variant.live

    # we want one normal variant from our product
    basket.set(variant, 1)

    # lets costumize the variant
    costum = variant.costumize()

    costum.additional_data['description'] = 'Green Frog Logo'

    # add two costumized varaints to the basket
    basket.set(costum, 2)

    # lets costumize the variant, again
    costum2 = variant.costumize()

    costum2.additional_data['description'] = 'Funky Frog Logo'

    # add five costumized varaints to the basket
    basket.set(costum2, 5)

    print basket.total_net, basket.total_vat, basket.total_price

    checkout_url = basket.order('https://success.com')
