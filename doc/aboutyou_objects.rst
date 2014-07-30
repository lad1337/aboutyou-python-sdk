Collins Object Structure
========================

A simple overview for the JSON objects the collins backend works with.

.. digraph:: objects

    node[shape=none];

    basket[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">basket</td></tr>
        <tr><td port="variant">order_lines</td><td></td></tr>
        <tr><td port="products">products</td><td></td></tr>
        <tr><td>total_price</td><td></td></tr>
        <tr><td>total_net</td><td></td></tr>
        <tr><td>total_vat</td><td></td></tr>
    </table>>];

    basket_order_line[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">order_line</td></tr>
        <tr><td>total_price</td><td></td></tr>
        <tr><td>total_net</td><td></td></tr>
        <tr><td>total_vat</td><td></td></tr>
        <tr><td>additional_data</td><td></td></tr>
        <tr><td port="product">product_id</td><td></td></tr>
        <tr><td port="variant">variant_id</td><td></td></tr>
        <tr><td>id</td><td></td></tr>
        <tr><td>tax</td><td></td></tr>
    </table>>];

    category[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">category</td></tr>
        <tr><td>id</td><td></td></tr>
        <tr><td>name</td><td></td></tr>
        <tr><td>active</td><td></td></tr>
        <tr><td>parent</td><td></td></tr>
        <tr><td>position</td><td></td></tr>
        <tr><td port="sub">sub_categories</td><td></td></tr>
    </table>>];

    product[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">product</td></tr>
        <tr><td port="id">id</td><td></td></tr>
        <tr><td>name</td><td></td></tr>
        <tr><td>description_long</td><td></td></tr>
        <tr><td>description_short</td><td></td></tr>
        <tr><td port="variant">default_variant</td><td></td></tr>
        <tr><td>min_price</td><td></td></tr>
        <tr><td>max_price</td><td></td></tr>
        <tr><td>sale</td><td></td></tr>
        <tr><td port="image">default_image</td><td></td></tr>
        <tr><td>attributes_merged</td><td></td></tr>
        <tr><td port="category">categories.appID</td><td></td></tr>
    </table>>];

    variant[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">variant</td></tr>
        <tr><td port="id">id</td><td></td></tr>
        <tr><td>ean</td><td></td></tr>
        <tr><td>price</td><td></td></tr>
        <tr><td>old_price</td><td></td></tr>
        <tr><td>retail_price</td><td></td></tr>
        <tr><td>default</td><td></td></tr>
        <tr><td port="attribute">attributes</td><td></td></tr>
        <tr><td port="image">images</td><td></td></tr>
        <tr><td>updated_date</td></tr>
        <tr><td>first_active_date</td></tr>
        <tr><td>first_sale_date</td></tr>
        <tr><td>created_date</td></tr>
        <tr><td>additional_info</td></tr>
        <tr><td>quantity</td></tr>
    </table>>];

    image[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">image</td></tr>
        <tr><td>hash</td><td></td></tr>
        <tr><td>ext</td><td></td></tr>
        <tr><td>mime</td><td></td></tr>
        <tr><td>size</td><td></td></tr>
        <tr><td>image</td><td>"width": 672, "height": 960</td></tr>
    </table>>];

    facet[label=<<table cellspacing="0" border="0" cellborder="1">
        <tr><td colspan="2">facet</td></tr>
        <tr><td>id</td><td></td></tr>
        <tr><td>facet_id</td><td></td></tr>
        <tr><td>group_name</td><td></td></tr>
        <tr><td>name</td><td></td></tr>
        <tr><td>value</td><td>if not group: brand</td></tr>
        <tr><td>options</td><td> if group: brand</td></tr>
    </table>>];


    basket:variant:w -> basket_order_line;
    basket:products:w -> product;
    basket_order_line:variant:w -> variant:id:w;
    basket_order_line:product:w -> product:id:w;
    product:category -> category;
    category:sub:w -> category;
    product:variant:w -> variant;
    variant:image:w -> image;
    variant:attribute -> facet;