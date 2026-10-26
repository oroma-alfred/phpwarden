"""phpwarden — PHP exposure and exploitation guard.

A general successor to the single-CVE php2shell checker: it assesses a PHP
environment against an evolving knowledge base of PHP CVEs (the feed), and can
watch PHP-FPM for active exploitation. The engine is open; the CVE feed is the
part a subscription keeps current.
"""
__version__ = "2.0.1"
