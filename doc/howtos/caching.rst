Caching
=======

Facets and Categories are always cached!
If you enable the extra caching Products and Variants will be also cached.

For caching is `pylibmc <http://sendapatch.se/projects/pylibmc/>`_ used.
To enable caching fill cache options in your configuration file.

.. code-block:: yaml

    entry_point_url: "http://ant-shop-api1.wavecloud.de/api"
    agent": "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36"
    image_url: "http://cdn.mary-paul.de/file/{}"
    product_url": "http://www.aboutyou.de/{}"
    shop_url: "https://checkout.aboutyou.de/"
    javascript_url: "//devcenter.mary-paul.de/apps/js/api.js"
    auto_fetch: true
    cache:
            hosts: ["127.0.0.1:11211"]
            timeout: 86400 # timeout in seconds
    logging: null


Starting local Memcached
------------------------

.. code-block:: bash

    >>> memcached -d -m 512 -l 127.0.0.1 -p 11211 -u nobody

Check if is running:

.. code-block:: bash

    >>> ps -eaf | grep memcached
