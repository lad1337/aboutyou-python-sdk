/**
 * Get the access token and write to cookie
 */
function get_token($) {
    var query_string = {};

    // get parameters and clean url.
    var params = window.location.href.split("#");

    if( params.length > 1 ) {
        var values = params[1].split("&");

        for (var i = 0; i < values.length; i++) {
            var pair = values[i].split("=");

            // If first entry with this name
            if (typeof query_string[pair[0]] === "undefined") {
                query_string[pair[0]] = pair[1];
            // If second entry with this name
            } else if (typeof query_string[pair[0]] === "string") {
                var arr = [ query_string[pair[0]], pair[1] ];
                query_string[pair[0]] = arr;
            // If third or later entry with this name
            } else {
                query_string[pair[0]].push(pair[1]);
            }
        }

        // set the cookie only if we got an access token
        if ( "access_token" in query_string) {
            $.cookie("aboutyou_access_token", query_string["access_token"], {'path': '/'});
            $.cookie("aboutyou_scope", query_string["scope"], {'path': '/'});
            $.cookie("aboutyou_token_type", query_string["token_token"], {'path': '/'});
        }
    }

    window.location.href = window.location.protocol + '//' + window.location.hostname;
}
