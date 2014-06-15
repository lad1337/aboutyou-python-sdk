#-*- encoding: utf-8 -*-
"""
:Author:    Arne Simon [arne.simon@slice-dice.de]

ShopApi is the attempt to make Api a little bit more userfriendly
and hides much of the direct calls to the Collins Api.
"""
from .api import Api, ApiException
from .config import Config
from .constants import PRODUCT_FIELD, TYPE

import bz2
import json
import logging
import uuid


class Node(object):
    """A simple wrapper around a dict object."""

    def __init__(self, shop, obj):
        self.shop = shop
        self.obj = obj

        if "error_message" in obj or "error_code" in obj:
            raise ApiException("{} {}".format(obj["error_code"], obj["error_message"]))

    def __getattr__(self, name):
        try:
            return self.obj[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, idx):
        return self.obj[idx]


class Category(Node):
    """
    The representation of a category in the category tree.

    .. rubric:: Iteration

    1. Over a category can be iterated to get the sub categories.

    .. code-block:: python

        >>> forest = shop.categories()
        >>> forest[0].name
        u'Damen'
        >>> for sub in forest[0]:
        ...     print sub.name
        ...
        Accessoires
        Ganzteile
        Oberteile
        Unterteile
        Schuhe
        Sport
        Wäsche & Bademode

    2. The category tree can be walked.

        >>> forest = shop.categories()
        >>> forest[0].name
        u'Damen'
        >>> for level, cat in forest[0].treeiter():
        ...     print level, '  '*level, cat.name
        ...
        0  Damen
        1    Accessoires
        2      Caps
        2      Gürtel
        2      Handschuhe
    """
    def __init__(self, shop, obj):
        super(Category, self).__init__(shop, obj)

        self.sub_categories = []

    def treeiter(self):
        """
        Walks the whole tree beginning from this node.

        :return: A tuple (level, :py:class:`aboutyou.shop.Category`).
        """
        def browse(level, node):
            yield level, node

            nextlevel = level + 1

            for sub in node.sub_categories:
                for child in browse(nextlevel, sub):
                    yield child

        return browse(0, self)

    def __iter__(self):
        for sub in self.sub_categories:
            yield sub

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name


class FacetGroup(object):
    """
    A container which holds a group of facets.

    .. code-block:: python

        >>> cups = shop.facet_group_by_id('cupsize')
        >>> cups.id
        4
        >>> for facet in cups:
        ...     print facet.id, facet.facet_id, facet.name
        ...
        4 96 D
        4 3671 DD
        4 3672 E
        4 3673 AA
        4 93 A
        4 94 B
        4 95 C

    """
    def __init__(self, fid, name, facets):
        self.id = fid
        self.name = name
        self.facets = facets

    def __getitem__(self, idx):
        return self.facets[idx]

    def __iter__(self):
        for facet in self.facets.values():
            yield facet

    def __len__(self):
        return len(self.facets)

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.name


class Image(Node):
    """
    Represents an image.
    """
    def __init__(self, shop, obj):
        super(Image, self).__init__(shop, obj)

    def url(self, width=None, height=None):
        """
        Returns the url to the image.
        """
        url = self.shop.api.config.image_url.format(self.hash)
        sizes = []

        if width:
            sizes.append('width={}'.format(width))

        if height:
            sizes.append('height={}'.format(height))

        if len(sizes) > 0:
            url += '?' + '&'.join(sizes)

        return url

    def __str__(self):
        return self.shop.api.config.image_url.format(self.hash)

    def __unicode__(self):
        return self.shop.api.config.image_url.format(self.hash)


class VariantAttributes(object):
    def __init__(self, shop, obj):
        self.obj = obj
        self.shop = shop

        prefixlen = len("attributes_")
        self.__data = {}

        for name, value in obj.items():
            grpid = int(name[prefixlen:])
            facets = shop.facet_group_by_id(grpid)

            collection = []
            for f in value:
                g = facets.facets.get(f, None)

                if g is None:
                    g = Node(shop, {'id': facets.id,
                                        'name': 'unknown_{}'.format(f),
                                        'value': 'unknown_{}'.format(f),
                                        'facet_id': f})
                    facets.facets[f] = g

                collection.append(g)

            self.__data[facets.name] = collection
            self.__data[facets.id] = collection

    def keys(self):
        return self.__data.keys()

    def __getitem__(self, idx):
        if idx in self.__data:
            return self.__data[idx]
        else:
            return []


class Variant(Node):
    """
    A variant of a Product.
    """
    def __init__(self, shop, obj):
        super(Variant, self).__init__(shop, obj)

        self._hash = obj['id']
        self._images = [Image(shop, i) for i in obj["images"]]
        self._attributes = VariantAttributes(shop, obj["attributes"])

    @property
    def images(self):
        """
        An array of :py:class:`aboutyou.shop.Image`.
        """
        return self._images

    @property
    def attributes(self):
        """
        The attributes aka facets of this product variant.
        """
        return self._attributes

    def live(self):
        """
        The live data to this variant.
        """
        return self.shop.api.livevariant([self.id])

    def costumize(self):
        """
        Returns a costumizeable instance of this variant.

        :return: :py:class:`aboutyou.shop.CostumizedVariant`
        """
        return CostumizedVariant(self)

    def __hash__(self):
        return self._hash


class CostumizedVariant(Variant):
    """
    A variant which can be costumized.

    .. code-block:: python

        >>> costum = variant.costumize()
        >>> costum.additional_data['description'] = 'my very own variant'
        >>> costum.additional_data['logo'] = 'A little froggy'
    """
    def __init__(self, variant):
        # super(type(self), self).__init__(variant.shop, variant.obj)
        self.obj = variant.obj
        self.shop = variant.shop
        self._images = variant._images
        self._attributes = variant._attributes

        # if we use uuid directly.
        # we get a "OverflowError: Python int too large to convert to C long"
        # when used with dictonarys.
        self._hash = hash(uuid.uuid4())

        self.additional_data = {'description': 'costumized'}

    def __hash__(self):
        return self._hash


class Product(Node):
    """
    A product with its variants.

    .. note::

        The Product class is an extensive user of the auto_fetch feature.
        If enabled in the configuration, when accessing a field which data
        is not present, for example the variants, then the variants will be
        automaticly requested.
    """
    def __init__(self, shop, obj):
        super(Product, self).__init__(shop, obj)

        self.__variants = None
        self.__categories = None
        self.__short_description = None
        self.__long_description = None
        self.__default_image = None
        self.__default_variant = None
        self.__styles = None

    def url(self):
        """
        Returns the url to the product in the shop.
        """
        slug = self.name.strip().replace(" ", "-") + "-" + str(self.id)
        return self.shop.api.config.product_url.format(slug)

    def __update_cache(self):
        self.shop.cache_set(str(self.obj['id']), self.obj)

    @property
    def categories(self):
        """
        :returns: A list of :py:class:`aboutyou.shop.Category`.
        """
        if self.__categories is None:
            catname = "categories.{}".format(self.shop.credentials.app_id)

            if catname not in self.obj and self.shop.config.auto_fetch:
                self.shop.log.debug('update categories from product %s', self.obj['id'])
                data = self.shop.api.products(ids=[self.id], fields=[PRODUCT_FIELD.CATEGORIES])
                self.obj.update(data["ids"][str(self.id)])

                self.__update_cache()

            self.__categories = [[self.shop.category_by_id(cid) for cid in path] for path in self.obj[catname]]

        return self.__categories

    @property
    def variants(self):
        """
        :returns: A list of :py:class:`aboutyou.shop.Variant`.
        """
        if self.__variants is None:

            if "variants" not in self.obj and self.shop.config.auto_fetch:
                self.shop.log.debug('update variants from product %s', self.obj['id'])
                data = self.shop.api.products(ids=[self.id],
                                                   fields=[PRODUCT_FIELD.VARIANTS])
                self.obj.update(data["ids"][str(self.id)])

                self.__update_cache()


            self.__variants = [Variant(self.shop, v) for v in self.obj["variants"]]

        return self.__variants

    @property
    def default_image(self):
        """
        The default image of this product.
        :returns: :py:class:`aboutyou.shop.Image`
        """
        if self.__default_image is None:
            if "default_image" not in self.obj and self.shop.config.auto_fetch:
                self.shop.log.debug('update default_image from product %s', self.obj['id'])
                data = self.shop.api.products(ids=[self.obj['id']], fields=[PRODUCT_FIELD.DEFAULT_IMAGE])
                self.obj.update(data["ids"][str(self.id)])

                self.__update_cache()

            self.__default_image = Image(self.shop, self.obj["default_image"])

        return self.__default_image

    @property
    def default_variant(self):
        """
        The default variant of this product.

        :returns: :py:class:`aboutyou.shop.Variant`.
        """
        if self.__default_variant is None:
            if "default_variant" not in self.obj and self.shop.config.auto_fetch:
                self.shop.log.debug('update default_variant from product %s', self.obj['id'])
                data = self.shop.api.products(ids=[self.obj['id']], fields=[PRODUCT_FIELD.DEFAULT_VARIANT])
                self.obj.update(data["ids"][str(self.obj['id'])])

                self.__update_cache()

            self.__default_variant = Variant(self.shop, self.obj["default_variant"])

        return self.__default_variant

    @property
    def styles(self):
        """
        The styles of this product.

        :returns: A list of :py:class:`aboutyou.shop.Product`.
        """
        if self.__styles is None:
            if "styles" not in self.obj and self.shop.config.auto_fetch:
                data = self.shop.log.debug('update styles from product %s', self.obj['id'])

                self.obj.update(data["ids"][str(self.obj['id'])])

                self.__update_cache()

            styles = []

            for pobj in self.obj['styles']:
                tmp = self.shop.cache_get(str(pobj['id']))

                if tmp is None:
                    tmp = pobj
                else:
                    tmp.update(pobj)

                self.shop.cache_set(str(tmp['id']), tmp)

                styles.append(Product(self.shop, tmp))

            self.__styles = styles

        return self.__styles

    def __getattr__(self, name):
        if not name.startswith('__') and name not in self.obj and self.shop.config.auto_fetch:
            self.shop.log.debug('update %s from product %s', name, self.obj['id'])
            data = self.shop.api.products(ids=[self.obj['id']],
                                               fields=[PRODUCT_FIELD.DESCRIPTION_SHORT,
                                                       PRODUCT_FIELD.DESCRIPTION_LONG,
                                                       PRODUCT_FIELD.SALE])
            self.obj.update(data["ids"][str(self.obj['id'])])

            self.__update_cache()

        return self.obj[name]

    def __hash__(self):
        return self.obj['id']


class ResultProducts(object):
    def __init__(self, search):
        self.search = search

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            start = idx.start
            if start is None:
                start = 0

            stop = idx.stop
            stop = min(stop, self.search.count)

            step = idx.step
            if step is None:
                step = 1

            buff = []

            if stop < 200:
                offset = 0
                count = stop
                buff = self.gather(0, stop)
            else:
                offset = 200 * int(start / 200)  # get clean step offset
                pos = offset
                count = (stop-offset)

                for i in xrange(count / 200):
                    buff += self.gather(pos, 200)
                    pos += 200

                if count % 200 != 0:
                    buff += self.gather(pos, 200)

            return [buff[i] for i in xrange(start-offset, count, step)]
        else:
            return self.gather(idx, 1)[0]

    def __len__(self):
        return self.search.count

    def __iter__(self):
        step = 200
        pos = 0
        # 'for' will not work, because 'count' can change each gather call.
        # for i in xrange(0, self.search.count):
        while pos < self.search.count:
            buff = self.gather(pos, step)

            for item in buff:
                yield item

            pos += step

    def gather(self, offset, limit):
        self.search.result['offset'] = offset
        self.search.result['limit'] = limit

        self.search.shop.log.debug('gather %s %s %s', self.search.sessionid, self.search.filter, self.search.result)

        response = self.search.shop.api.product_search(self.search.sessionid, filter=self.search.filter, result=self.search.result)

        # the result count can change ANY request !!!
        self.search.count = response['product_count']

        self.search.shop.log.debug('result count %s : %s', len(response['products']), response['product_count'])

        buff = []
        for p in response["products"]:
            pobj = self.search.shop.cache_get(str(p["id"]))

            if pobj:
                pobj.update(p)
            else:
                pobj = p

            self.search.shop.cache_set(str(pobj['id']), pobj)
            buff.append(Product(self.search.shop, pobj))

        return buff


class Search(object):
    """
    Representing an initiated search.
    """
    def __init__(self, shop, sessionid, filter=None, result=None):
        self.shop = shop
        self.sessionid = sessionid
        self.filter = filter
        self.categories = {}

        if result is None:
            self.result = {"limit": 0, "offset": 0}
        else:
            self.result = result
            self.result["limit"] = 0
            self.result["offset"] = 0

        self.obj = self.shop.api.product_search(self.sessionid, filter=self.filter, result=self.result)

        self.count = self.obj["product_count"]

        self.products = ResultProducts(self)

        if "categories" in self.obj["facets"]:
            for el in self.obj["factes"]["categories"]:
                cat = self.shop.category_by_id(el["term"])
                self.categories[cat] = el["count"]


class BasketException(Exception):
    def __init__(self, msg, fine, withError):
        super(BasketException, self).__init__(msg)

        self.fine = fine
        self.withError = withError


class Basket(object):
    """
    An object which wrappes the shop basket for a session id.

    This object is normaly not instaced directly, instead it is optained
    from the ShopApi instace by a call to :py:func:`aboutyou.shop.ShopApi.basket`.

    .. code-block:: python

        >>> basket = shop.basket('s3ss10n')

    :param shop: The ShopApi instance.
    :param sessionid: The session id the basket is associated with.
    """
    def __init__(self, shop, sessionid):
        self.shop = shop
        self.sessionid = sessionid
        self.obj = None

        self.variants = {}
        self.basket_ids_by_variant = {}

    def __getattr__(self, name):
        return self.obj[name]

    def _check_obj(self):
        withError = []
        fine = []

        for line in self.obj['order_lines']:
            if 'error_message' in line:
                withError.append(line)
            else:
                fine.append(line)

        if len(withError) > 0:
            msg = '\n'.join((i['error_message'] for i in withError))
            self.shop.log.error(msg)
            self.shop.log.error(json.dumps(self.obj, indent=4))
            raise BasketException(msg, fine, withError)

    def set(self, variant, count):
        """
        Sets the *count* of the *variant* in the basket.

        :param variant: :py:class:`aboutyou.shop.Variant` or :py:class:`aboutyou.shop.CostumizedVariant`
        :param int count: The amount of the items. If set to 0 the item is removed.
        :raises BasketException: If there is an error in the basket.
        """
        def push_ids(ids):
            vid = variant.id
            if isinstance(variant, CostumizedVariant):
                additional = variant.additional_data
                basketset = [(i, vid, additional) for i in ids]
            else:
                basketset = [(i, vid) for i in ids]

            self.obj = self.shop.api.basket_set(self.sessionid, basketset)


        if count < 1 and variant in self.basket_ids_by_variant:
            self.obj = self.shop.api.basket_remove(self.sessionid, self.basket_ids_by_variant[variant])

            del self.basket_ids_by_variant[variant]
            del self.variants[variant]

        else:
            if variant in self.variants:
                delta = count - self.variants[variant]

                if delta > 0:
                    ids = [uuid.uuid4().hex for unused in xrange(delta)]
                    self.basket_ids_by_variant[variant] += ids

                    push_ids(ids)

                elif delta < 0:
                    to_remove = self.basket_ids_by_variant[variant][:-delta]
                    self.basket_ids_by_variant[variant] = self.basket_ids_by_variant[variant][-delta:]

                    self.obj = self.shop.api.basket_remove(self.sessionid, to_remove)

            else:
                self.variants[variant] = count

                ids = [uuid.uuid4().hex for unused in xrange(count)]
                self.basket_ids_by_variant[variant] = ids

                push_ids(ids)

            self._check_obj()


    def order(self, success_url, cancel_url=None, error_url=None):
        """
        Begins to order this basket.

        :param str success_url: this is a callback url if the order was successfully created.
        :param str cancel_url: this is a callback url if the order was canceled.
        :param str error_url: this is a callback url if the order throwed exceptions.
        :returns: The url to the shop.
        """
        self.shop.log.info('order basket %s', self.sessionid)
        return self.shop.api.order(self.sessionid, success_url, cancel_url, error_url)

    def dispose(self):
        """
        Removes all items from the basket and disassociates this basket with the session id.
        """
        self.shop.log.debug('dispose basket %s', self.sessionid)

        self.shop.api.basket_dispose(self.sessionid)

        del self.shop._baskets[self.sessionid]


class ShopApi(object):
    """
    An abstraction layer around the thin Api api.

    .. note::

        If caching is not set to *null* in the config file, ShopApi will
        cache Factes and the Category-Tree.

    :param credentials: A :py:class:`aboutyou.config.Credentials` instance.
    :param config: A :py:class:`aboutyou.config.Config` instance.
    """
    def __init__(self, credentials, config=Config()):
        self.credentials = credentials
        self.config = config
        self.api = Api(self.credentials, self.config)

        logname = "aboutyou.shop.{}".format(self.credentials.app_id)
        self.log = logging.getLogger(logname)

        self.__categorytree = None
        self.__category_ids = {}
        self.__category_names = {}

        self.__facet_map = None
        self.__facet_groups = []

        self.__simple_colors = None

        self._baskets = {}

        self.cache = None

        if self.config.cache is not None and len(self.config.cache) > 0:
            try:
                import pylibmc

                self.cache = pylibmc.Client(self.config.cache['hosts'],
                                            binary=True,
                                            behaviors={"tcp_nodelay": True, "ketama": True})

                try:
                    self.cache.get('TEST_TOKEN')
                    self.log.info('use memcached via pylibmc')
                except pylibmc.ConnectionError:
                    self.cache = None
                    self.log.warn('no caching used')

            except ImportError:
                self.cache = None
                self.log.warn('no caching used')

    def __build_categories(self):
        tree = self.cache_get('categorytree')

        if tree:
            self.log.info('use cached category tree')
        else:
            self.log.info('get category tree from Api')
            tree = self.api.categorytree()

            self.cache_set('categorytree', tree)

        def build(n):
            c = Category(self, n)
            self.__category_ids[c.id] = c
            self.__category_names[c.name] = c
            c.sub_categories = [build(x) for x in n["sub_categories"]]
            return c

        self.__categorytree = [build(node) for node in tree]

    def __build_facets(self):
        # facets = self.cache_get('facettypes')
        response = self.cache_get('facets')

        if response:
            self.log.info('use cached facets')
        else:
            # facets = self.api.facettypes()
            response = self.api.facets([])["facet"]

            # self.cache_set('facettypes', facets)
            self.cache_set('facets', response)

        self.__facet_map = {}
        for facet in response:
            fobj = Node(self, facet)
            group = self.__facet_map.get(fobj.group_name)
            if group is None:
                group = FacetGroup(fobj.id, fobj.group_name, {})
                self.__facet_map[group.name] = group
                self.__facet_map[group.id] = group
                self.__facet_groups.append(group)

            group.facets[fobj.facet_id] = fobj

    def cache_set(self, key, value):
        if self.cache is not None:
            self.log.debug('cache %s', key)
            self.cache.set(key, bz2.compress(json.dumps(value)), time=self.config.cache['timeout'])

    def cache_get(self, key):
        if self.cache is not None:
            data = self.cache.get(key)

            if data:
                self.log.debug('get from cache %s', key)
                return json.loads(bz2.decompress(data))
            else:
                self.log.debug('cache could not finde %s', key)

    def javascript_url(self):
        """
        Returns the url to the Aboutyou Javascript helper functions.
        """
        return self.api.javascript_url()

    def javascript_tag(self):
        """
        Generates a HTML script tag with the url to the Aboutyou Javascript helper functions.
        """
        return self.api.javascript_tag()

    def basket(self, sessionid):
        """
        Returns a basket for the session id.

        :param sessionid: The session id the basket is associated with.
        :returns: :py:class:`aboutyou.shop.Basket`
        """
        if sessionid in self._baskets:
            return self._baskets[sessionid]
        else:
            basket = Basket(self, sessionid)

            self._baskets[sessionid] = basket

            return basket

    def categories(self):
        """
        Returns the category tree.

        :returns: A list of :py:class:`aboutyou.shop.Category`.

        .. code-block:: python

            >>> forest = shop.categories()
            >>> forest[0].name
            u'Damen'
            >>> for level, cat in forest[0].treeiter():
            ...     print level, '  '*level, cat.name
            ...
            0  Damen
            1    Accessoires
            2      Caps
            2      Gürtel
            2      Handschuhe

        """
        if self.__categorytree is None:
            self.__build_categories()

        return self.__categorytree


    def category_by_id(self, cid):
        """
        Returns the category with the given id.

        :param cid: The id of the category to get.
        :returns: A :py:class:`aboutyou.shop.Category` instance.

        .. code-block:: python

            >>> cat = shop.category_by_id(123)
        """
        if self.__categorytree is None:
            self.__build_categories()

        return self.__category_ids[cid]

    def category_by_name(self, name):
        """
        Returns the category with the given name.

        .. note:: If there are more than one category with the same name.
                    The last inserted category will be returned.

        :param str name: The name of the category.
        :returns: A :py:class:`aboutyou.shop.Category` instance.

        .. code-block:: python

            >>> cat = category_by_name('Damen')
        """
        if self.__categorytree is None:
            self.__build_categories()

        return self.__category_names[name]

    def simple_colors(self):
        """
        Returns an array of facet colors which are a simple selection out
        of the hugh possebilities.
        """
        if self.__facet_map is None:
            self.__build_facets()

        if self.__simple_colors is None:
            self.log.info('build simple colors')

            colors = self.facet_group_by_id('color')
            self.__simple_colors = []
            for fid in [570, 168, 67, 247, 48, 14, 18, 204, 30, 1, 579, 15, 12,
                        11, 55, 580, 9, 333, 646]:
                self.__simple_colors.append(colors[fid])

        return self.__simple_colors


    def facet_groups(self):
        """
        :retuns: A list of all known facet groups.
        """
        if self.__facet_map is None:
            self.__build_facets()

        return self.__facet_groups


    def facet_group_by_id(self, facet_group):
        """
        Returns all facets of a group.

        :param facet_group: The id or name of the facet group.
        :returns: A :py:class:`aboutyou.shop.FacetGroup` instance.

        .. code-block:: python

            >>> cups = shop.facet_group_by_id('cupsize')
        """
        if self.__facet_map is None:
            self.__build_facets()

        return self.__facet_map[facet_group]


    def products_by_id(self, pids, fields=['sale', 'active', 'default_variant']):
        """
        Gets a products by its id.

        :param list pids: A list of product ids.
        :returns: A tuple of a dict of :py:class:`aboutyou.shop.Product` instances
                  and a dict with ids and error message which cause trouble.

        .. rubric:: Example

        .. code-block:: python

            >>> products, with_error = shop.products_by_id([237188, 123])
            >>> products
            {237188: <aboutyou.shop.Product object at 0x7f1cd211ee50>}
            >>> with_error
            {123: [u'product not found']}

        """
        spid = []
        products = {}
        withError = {}

        # get products from cache or mark unknown products
        if self.cache is not None:
            for pid in pids:
                sid = str(pid)
                p = self.cache_get(sid)

                if p is None:
                    spid.append(sid)
                else:
                    pro = Product(self, p)
                    products[pro.id] = pro
        else:
            spid = [str(p) for p in pids]

        if len(spid) > 0:
            response = self.api.products(ids=pids, fields=list(fields))
            new = []

            for pid, p in response["ids"].items():
                if "error_message" in p:
                    withError[int(pid)] = p['error_message']
                else:
                    product = Product(self, p)
                    new.append(product)
                    products[product.id] = product

            if self.cache is not None:
                for n in new:
                    self.cache_set(str(n.id), n.obj)

        return products, withError

    def products_by_ean(self, eans, fields=None):
        """
        Gets products by its ean code.

        :param list eans: A list of eans.
        :param list fields: An array of product fields.
        :returns: A :py:class:`aboutyou.shop.Product` instance.
        """
        response = self.api.product_eans(eans=eans)

        return [Product(self, p) for p in response]


    def search(self, sessionid, filter=None, result=None):
        """
        Creates a new :py:class:`aboutyou.shop.Search` instance.

        .. note::

            For filter and result values see :py:func:`aboutyou.api.Api.product_search`.

        :param sessionid: The user session id.
        :returns: A :py:class:`aboutyou.shop.Search` instance.

        .. code-block:: python

            >>> search = shop.search('s3ss10n',
            ...                      filter={"categories": [19675],
            ...                             "facets":{FACET.COLOR: [168]},},
            ...                      result={"fields": ["active", "variants"]})
            >>> search.count
            3
            >>> search.products
            <aboutyou.shop.ResultProducts object at 0x7f396cb3ef90>
            >>> for product in search.products:
            ...     print product.id, product.name
            ...
            246823 Puma Sneaker, »Drift Cat 4 MAMGP N«
            217290 Puma Future Cat M1 Big SF NM, Freizeitschuh
            366853 PUMA Herren MERCEDES AMG PETRONAS Sneaker Drift Cat 5
            >>> search.products[1:2]
            [<aboutyou.shop.Product object at 0x7f992a20ead0>]

        """
        return Search(self, sessionid, filter, result)


    def autocomplete(self, searchword, types=None, limit=None):
        """
        Autocompletes the searchword and looks in the products and/or
        categories for autocompletion possebilities.

        :param str searchword: The abbriviation.
        :param list types: against which types should be autocompleted.
                            The oprions are :py:class:`aboutyou.constants.TYPES`
        :param int limit: the amount of items returned per selected type
        :returns: A tuple of two list. First one are the products and the second
                 are the categories.

        .. rubric:: Example

        .. code-block:: python

            >>> products, categories = shop.autocomplete("sho")
        """
        result = self.api.autocomplete(searchword, types=types, limit=limit)

        products = []
        if types is None or TYPE.PRODUCTS in types:
            for p in result["products"]:
                pobj = Product(self, p)
                products.append(pobj)

        categories = []
        if types is None or TYPE.CATEGORIES in types:
            if self.__categorytree is None:
                self.__build_categories()

            for c in result["categories"]:
                scid = c["id"]

                if scid in self.__category_ids:
                    categories.append(self.__category_ids)
                else:
                    raise ApiException("unknown category {}".format(scid))

        return products, categories

    def suggest(self, searchword, categories=None, limit=None):
        """
        Suggest additional words to the provided searchword.

        :param str searchword: A search string to suggest items for.
        :param list categories: A list of :py:class:`aboutyou.shop.Category`.
        :param int limit: The maximum amount of results.
        :returns: A list of strings.
        """
        if categories is not None:
            categoriescast = [c.id for c in categories]
        else:
            categoriescast = None

        result = self.api.suggest(searchword, categories=categoriescast, limit=limit)
        return result
