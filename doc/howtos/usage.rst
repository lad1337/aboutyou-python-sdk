Usage
=====

.. contents::


Configuration
-------------

The SDK has to be configured for your connection.
The SDK comes with four instances:

    * :py:class:`aboutyou.config.Config`
    * :py:class:`aboutyou.config.YAMLConfig`
    * :py:class:`aboutyou.config.JSONConfig`
    * :py:class:`aboutyou.config.JSONEnvironmentFallbackConfig`

And three credential classes.

    * :py:class:`aboutyou.config.Credentials`
    * :py:class:`aboutyou.config.YAMLCredentials`
    * :py:class:`aboutyou.config.JSONCredentials`


A good practice is to use the YAML classes, so your app-id and password
are not hard coded in the source code and YAML provides a nice and user-friendly
data layout.

Simple Setup
++++++++++++

If you just want the API working and have no special needs.
Then use the :py:class:`aboutyou.config.Credentials` class direktly.

.. code-block:: python
    :linenos:

    from aboutyou.config import Credentials
    from aboutyou.api import Api

    credentials = Credentials(app_id=101, app_token="<yourtoken>")
    client = Api(credentials)

    tree = client.categorytree()

This mayby a good setup for testing and getting used to the API, but not wise
for production environmnet.

A Real Life Setup
+++++++++++++++++

If you plan to go in production, you want a little more controle over whats going on.
Which leads to more configuration, you do not want to have directly in your code.

Here is an example of how to use the YAML configuration file.

.. code-block:: python
    :linenos:

    from aboutyou.config import YAMLConfig, YAMLCredentials
    from aboutyou.api import Aboutyou

    client = Aboutyou(YAMLCredentials('mycredentials.yml'), YAMLConfig('myconfig.yml'))

    print client.credentials.app_id
    print client.config.auto_fetch

.. rubric:: mycredentials.yml

.. literalinclude:: ../../examples/credentials.yml
    :language: yaml
    :linenos:

.. rubric:: myconfig.yml

.. literalinclude:: ../../examples/config.yaml
    :language: yaml
    :linenos:


Extending the Config
++++++++++++++++++++

Maybe you want to read your configuration from another source.
It is easy to archive, by extending the :py:class:`aboutyou.config.Config` class.

.. literalinclude:: ../../examples/extending_config.py
    :language: python
    :linenos:


This is of course allthough possible for the Credentials.


Getting the Brand
-----------------

.. literalinclude:: ../../examples/get_brand.py
    :language: python
    :linenos:


Category Tree
-------------

.. literalinclude:: ../../examples/category_tree.py
    :language: python
    :linenos:


Using the Basket
----------------

.. literalinclude:: ../../examples/basket.py
    :language: python
    :linenos:


Search
------

One of the most likely things you will do with the Aboutyou-API is to search.
So here are some more extensive examples to make your self familiar with the
Python version of the Aboutyou-API-SDK. Have Fun :)


Search for Colors in Categories
+++++++++++++++++++++++++++++++

.. code-block:: python
    :linenos:

    import codecs

    from aboutyou.shop import ShopApi
    from aboutyou.config import YAMLCredentials
    from aboutyou.constants import FACET

    shop = ShopApi(YAMLCredentials("my-config.yml"))

    filters = {"categories":[19631, 19654],
               "facets":{FACET.COLOR: [1,9]}}

    result = shop.search('s3ss10n', filter=filters)

    with codecs.open("dump.txt", "w", encoding="utf8") as o:
        for p in result.products:
            o.write(u"{} {} {}\n".format(p.id, p.name, p.active))
            for v in p.variants:
                # o.write(u"{}".format(v.obj))
                o.write(u"    {} {}\n".format(v.id, v.quantity))
                o.write(u"        {}\n".format([ (f.facet_id, f.name) for f in v.attributes["color"]]))

