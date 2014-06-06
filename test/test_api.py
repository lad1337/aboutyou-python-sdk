#-*- encoding: utf-8 -*-
"""
:Author:    Arne Simon [arne.simon@slice-dice.de]
"""
from aboutyou.constants import FACET
from aboutyou.api import AboutYouException

import json
from pytest import raises


def test_autocomplete(aboutyou, mock):
    data = mock('autocomplete-sho.json')
    result = aboutyou.autocomplete('sho', limit=10)
    assert result == data[0]['autocompletion']


def test_suggest(aboutyou, mock):
    data = mock('suggest.json')
    result = aboutyou.suggest('sho')

    assert result == data[0]['suggest']


class TestBasket:

    def test_set(self, aboutyou, session, mock):
        data = mock('basket.json')
        result = aboutyou.basket_set(session, [['id1', 4719964],])

        assert result == data[0]['basket']

    def test_invalid(self, aboutyou, session, mock):
        data = mock('basket-set-with-int-id.json')

        with raises(AboutYouException):
            result = aboutyou.basket_set(session, [[4719964, 4719964],])

            assert result == data[0]['basket']

    def test_get(self, aboutyou, session, mock):
        data = mock('basket.json')
        result = aboutyou.basket_get(session)

        assert result == data[0]['basket']

    def test_remove(self, aboutyou, session, mock):
        data = mock('basket.json')
        result = aboutyou.basket_remove(session, ['my4813890'])

    def test_dispose(self, aboutyou, session, mock):
        data = mock('basket.json')
        aboutyou.basket_dispose(session)

    def test_get_order(self, aboutyou, mock):
        data = mock('get-order.json')
        result = aboutyou.get_order('123455')

        assert result == data[0]['get_order']

    def test_order(self, aboutyou, session, mock):
        data = mock('initiate-order.json')
        aboutyou.order(session, 'https://success.com')


def test_category(aboutyou, mock):
    data = mock('category.json')
    result = aboutyou.category([16138])

    assert result['16138'] == data[0]['category']['16138']


def test_categorytree(aboutyou, mock):
    data = mock('category-tree.json')
    result = aboutyou.categorytree()

    assert result == data[0]['category_tree']


def test_facets(aboutyou, mock):
    data = mock('facets-0.json')
    result = aboutyou.facets([FACET.BRAND])

    assert result == data[0]['facets']


def test_facettypes(aboutyou, mock):
    data = mock('facet-types.json')
    result = aboutyou.facettypes()

    assert result == data[0]['facet_types']


# def test_livevariant(aboutyou, log):
#     response = aboutyou.livevariant([4813890])

def test_child_apps(aboutyou, mock):
    data = mock('child-apps.json')
    result = aboutyou.child_apps()

    assert result == data[0]['child_apps']['child_apps']


def test_products(aboutyou, mock):
    data = mock('products.json')
    result = aboutyou.products([123, 456])

    assert result == data[0]['products']


def test_producteans(aboutyou, mock):
    data = mock('result/products_eans.json')
    result = aboutyou.producteans([8806159322381])

    assert result == data[0]['products_eans']['eans']


def test_productsearch(aboutyou, session, mock):
    data = mock('search/product_search.json')
    result = aboutyou.productsearch(session)

    assert result == data[0]['product_search']
