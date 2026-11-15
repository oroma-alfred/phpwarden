# Edge protection and the shield

The shield runs inside PHP. It knows which vulnerable components a site has and
checks requests for exactly those, and it rate-limits login, xmlrpc and
password-reset endpoints per client. It cannot do what only something in front
of the server can:

| | edge (Cloudflare, nginx, host WAF) | phpwarden shield |
|---|---|---|
| volumetric DDoS, connection floods | yes | **no**: every request still reaches PHP |
| TLS | yes | no |
| CAPTCHA / JavaScript challenges, bot scoring | yes (plan-dependent) | no |
| static files, non-PHP paths | yes | no (it runs only for PHP requests) |
| rules for the exact vulnerable plugins/packages installed | generic | yes |
| per-client limits on login / xmlrpc / reset | yes (rules you write) | yes (defaults, log first) |

Use both. The edge absorbs volume; the shield covers what is specific to the site
and keeps working if the edge is bypassed (origin IP leaked, a host without a CDN).

## Cloudflare

Feature availability depends on your plan and changes over time; check
Cloudflare's own documentation (developers.cloudflare.com) for each item.

1. **Proxy on.** DNS records for the site set to *Proxied* (orange cloud).
   Without it Cloudflare does nothing for HTTP traffic.
2. **Under Attack mode** during an active attack only (Security settings). It
   puts a JavaScript challenge in front of every visitor; turn it off after.
3. **Rate-limiting rule for `/wp-login.php`** (Security → WAF → Rate limiting
   rules). Example: URI path equals `/wp-login.php` and method `POST`, a few
   requests per minute per IP, action *Block* or *Managed Challenge*.
   *Plan-dependent:* the number of rules, counting periods and characteristics
   differ between Free, Pro, Business and Enterprise. Add `/xmlrpc.php` too, or
   block it outright if nothing uses it (Jetpack and some apps do).
4. **WAF managed rules** if your plan includes them (*paid plans*). They are
   generic; the shield's rules are for your installed components. They overlap
   without conflicting.
5. **Real client IP for the shield.** Behind Cloudflare every request comes from
   a Cloudflare address, so per-client limits would see a handful of "clients".
   Cloudflare sends the visitor's address in `CF-Connecting-IP`. Tell the shield
   to trust it only from Cloudflare by putting Cloudflare's ranges in the policy:

   ```json
   "trust_proxy": ["173.245.48.0/20", "103.21.244.0/22", "...", "2400:cb00::/32", "..."]
   ```

   Take the current list from https://www.cloudflare.com/ips-v4 and
   https://www.cloudflare.com/ips-v6 (it changes; refresh it when you rebuild the
   policy). These ranges are **not** trusted by default: on a site that is not
   behind Cloudflare, trusting them would let anyone set their own client IP. The
   shield uses `CF-Connecting-IP` (then the right-most `X-Forwarded-For` entry
   that is not itself a trusted proxy) only when `REMOTE_ADDR` is inside a listed
   range; from any other peer those headers are ignored.

   If your web server already rewrites `REMOTE_ADDR` (nginx `real_ip`, Apache
   `mod_remoteip`), leave `trust_proxy` empty: PHP already sees the visitor.

## nginx

Rate-limit at nginx as well when you control it; it rejects before PHP starts.

```nginx
# http {}
limit_req_zone $binary_remote_addr zone=wplogin:10m rate=6r/m;
limit_req_zone $binary_remote_addr zone=xmlrpc:10m  rate=30r/m;

# server {}
location = /wp-login.php {
    limit_req zone=wplogin burst=5 nodelay;
    limit_req_status 429;
    include fastcgi_params;            # your usual PHP handler
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass php;
}
location = /xmlrpc.php {
    limit_req zone=xmlrpc burst=10 nodelay;
    limit_req_status 429;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass php;
}
```

`limit_req` counts GETs too (the login form page); the rates above leave room
for that. Behind Cloudflare, set the real client address first
(`set_real_ip_from <each Cloudflare range>; real_ip_header CF-Connecting-IP;`),
otherwise the zone keys on Cloudflare's addresses.

## Check that the real client IP reaches PHP

1. Put a temporary file in the web root (delete it after):

   ```php
   <?php header('Content-Type: text/plain');
   foreach (['REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
       echo $k, ': ', $_SERVER[$k] ?? '-', "\n";
   }
   ```

2. Open it from a phone on mobile data (not your office network) and compare
   with what a "what is my IP" page says.
   - `REMOTE_ADDR` is your phone's address: nothing to do, leave `trust_proxy` empty.
   - `REMOTE_ADDR` is a proxy/Cloudflare address and the header shows yours: add
     that proxy's ranges to `trust_proxy`.
3. After rebuilding the policy, trip a limit on purpose in log mode (11 wrong
   logins from the phone) and check that the shield log's `ip` is the phone's
   address, not the proxy's. `phpwarden shield report` showing one client for
   all traffic means the IP is still wrong.
