"""WordPress model: request sources, REST/AJAX entry points, $wpdb, options,
redirects, and the nonce/capability authorization model."""
from __future__ import annotations

from phpwarden import code as _code

SOURCE_FUNCS = frozenset({"get_query_var", "filter_input", "filter_input_array", "wp_get_raw_referer",
                          "get_search_query_raw"})
# get_search_query() escapes by default; get_query_var() does not.
REST_REQUEST_CLASS = "wp_rest_request"
REST_SOURCE_METHODS = frozenset({"get_param", "get_params", "get_json_params", "get_body_params", "get_query_params",
                                 "get_url_params", "get_file_params", "get_body", "offsetget", "get_header",
                                 "get_headers", "get_default_params"})
WPDB_READ_SINKS = ("query", "get_results", "get_var", "get_row", "get_col")
WPDB_WRITES = frozenset(_code.WPDB_WRITES)
WP_WRITES = frozenset(_code.WP_WRITES)
WP_GUARDS = frozenset(_code.WP_GUARDS)
WP_NONCES = frozenset(_code.WP_NONCES)
# functions whose key argument names the stored setting (index of the key)
OPTION_KEY_SINKS = {"update_option": 0, "add_option": 0, "delete_option": 0, "update_site_option": 0,
                    "set_site_transient": 0, "update_term_meta": 1, "update_comment_meta": 1,
                    "update_user_meta": 1, "add_user_meta": 1, "update_post_meta": 1, "add_post_meta": 1,
                    "update_user_option": 1, "set_transient": 0}
# reads of a stored option / meta value: function -> index of the key argument
STORED_READS = {"get_option": 0, "get_site_option": 0, "get_transient": 0, "get_post_meta": 1,
                "get_user_meta": 1, "get_term_meta": 1, "get_comment_meta": 1, "get_user_option": 0}
REDIRECT_SAFE = frozenset({"wp_safe_redirect"})
HOOK_FUNCS = frozenset({"add_action", "add_filter"})
