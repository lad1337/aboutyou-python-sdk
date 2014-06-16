AboutYou-Shop-SDK
=================

**Author:** Arne Simon [arne.simon@silce-dice.de]


A Python implementation for the AboutYou shop API.


Installation
------------

Install the package via PIP::

    $ pip install aboutyou

Or checkout the most recent version::

    $ git clone https://bitbucket.org/slicedice/aboutyou-shop-sdk-python.git
    $ cd aboutyou-shop-sdk-python
    $ python setup.py install


Quick Start
-----------

1. Register for an account at the [AboutYou Devcenter](https://developer.aboutyou.de/) and create a new app.
   You will be given credentials to utilize the About You API.
2. Modefiy one of the example credential files.
3. Use the following lines::

    from aboutyou.config import YAMLCredentials
    from aboutyou.shop import ShopApi

    shop = ShopApi(YAMLCredentials('mycredentials.yml'))
    cagtegory_forest = shop.categories()


Documentation
-------------

Documentation is found at http://aboutyou-shop-sdk.readthedocs.org/en/latest/.

If you want to build the documentation yourself.

1. Checkout the git repo.
2. Go to the *doc/* folder.
3. make html


Change Log
----------

- 1.0:
    * Added Django backend and middleware
    * Fixed configuration bug
    * Cleand up project structure
    * setup.py is not dependent on setuptools

- 0.9
    * Is now Python 3 compatible.
    * Test cases with mocking.
    * Added Auth module.
    * Moved thin api wrapper in own api module.
    * The app credentials are now seperated from the other configurations.

- 0.3:
    * Additional docmentation.
    * Auto fetch flag.
    * PyPI integration.
    * YAML configuration files.

- 0.2:
    * Caching with Memcached and pylibmc.
    * EasyAboutYou has function, *getSimpleColors*.
    * Error handling fix.

- 0.1:
    * Products return now there url to the mary+paul shop.
    * Dirty caching without memcached.
    * EasyCollins products are no bulk requests.
    * Extended documentation for EasyAboutYou.
