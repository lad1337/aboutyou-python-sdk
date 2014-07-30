How To use with Django
======================

Some examples how to use the SDK with Django.

Setup
-----

It is a good practice to put an instance of :py:class:`aboutyou.api.Api` or
:py:class:`aboutyou.shop.ShopApi` in the *settings.py* of django, so
the entire application can access one instance.

**settings.py**

.. code-block:: python
    :linenos:

    ABOUTYOU = None

    try:
        from aboutyou.config import YAMLCredential
        from aboutyou.shop import ShopApi
        from aboutyou.auth import Auth

        credentials = YAMLCredential('myconfig.yml')
        ABOUTYOU = ShopApi(credentials)
        AUTH = Auth(credentials)
    except Exception:
        logger.exception('No AboutYou API!!!')


Search Template Tag
-------------------

.. rubric:: templatetags/search.py

.. code-block:: python
    :linenos:

    from django import template
    from django.conf import settings

    from aboutyou.constants import FACET

    import logging

    register = template.Library()
    logger = logging.getLogger("aboutyou.templatetags")

    def buildproduct(p):
        return {
            "id": p.id,
            "vid": p.default_variant.id,
            "name": p.name,
            "url": p.default_variant.images[0].url(150, 150),
            # remeber prices are all in Euro Cent, so format
            "price": '{:.2f}'.format(float(p.default_variant.price)/100.0).replace('.', ','),
            # filter unknown brands
            "brands": ', '.join([f.name for f in p.default_variant.attributes['brand'] if not f.name.startswith('unknown')]),
        }

    @register.assignment_tag
    def search(catgeoryid, session):
        try:
            if session.session_key is None:
                session.cycle_key()

            filters = {
                        "categories": [catgeoryid],
                        "facets": {FACET.COLOR: [product.color]},
                    }

            result = {
                "fields": ["variants", "active", "description_short",
                            "description_long", "default_variant"]
            }

            search = settings.ABOUTYOU.search(session.session_key, filters, result)

            prods = search.products[:20]

            return [buildproduct(p) for p in prods]
        except Exception:
            logger.exception('')

        return None

.. note::

    The function *buildproduct* builds a dict from the :py:class:`aboutyou.shop.Product`
    instance, because accessing functions in Django Template-Tags can be rather
    tricky. Thats why we choose a prepared *dict* here.

.. rubric:: templates/product.html

.. code-block:: html
    :linenos:

    {% search catgeoryid request.session as result %}
    {% if result|length > 0 %}
        <h2 class="productHeading">
            <div class="marker">{{ forloop.counter }}</div>
            Produktvorschl&auml;ge
        </h2>

        {% for p in result %}
        <a class="" href="#" title="{{ p.name }}" target="_blank" data-id="{{ p.id }}" data-variant="{{ p.vid }}">
            <div class="product">
                <img class="productImg" src="{{ p.url }}" alt="{{ p.name }}" />
            </div>
            <p class="title truncate">{{ p.name }}</p>
            {% if p.brands != '' %}<p class="brand">{{ p.brands }}</p>{% endif %}
            <p class="price">{{ p.price }} &euro;</p>
        </a>
        {% endfor %}
    {% endif %}
