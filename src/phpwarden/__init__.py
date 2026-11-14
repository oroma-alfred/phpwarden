"""phpwarden: a PHP vulnerability scanner.

It checks the PHP engine, Composer dependencies, WordPress, your own code and
the live site against a feed of known vulnerabilities, ranks findings by
real-world exploitation (CISA KEV, then EPSS, then CVSS), and can watch PHP-FPM
for active exploitation. The engine and the bundled feed are open; free users
get weekly feed updates, and a subscription adds the feed rebuilt twice a day.
"""
__version__ = "2.2.0"
