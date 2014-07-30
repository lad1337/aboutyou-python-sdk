Difference between ShopApi and Api
==================================

In the aboutyou package are two Collins API implementations.

1. The first one, :py:class:`aboutyou.api.Api`, is a thin python wrapper which takes Python dict's and list's and returns the
   result as the same. This allows the user of the SDK to create highly costumized requests.

2. The second, :py:class:`aboutyou.shop.ShopApi`, which is a more convient layer of abstraction of the Collins API.
   Category trees and facets are cached, the dicts are wrapped in objects and know there relation.
   The down part is, that this features comes a the cost of speed.

