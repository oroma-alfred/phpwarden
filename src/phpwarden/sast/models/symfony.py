"""Symfony model: Request bags, controller entry points, Doctrine, Twig, Process,
Response and the HTTP client."""
from __future__ import annotations

import os
import re

REQUEST_CLASS = "symfony\\component\\httpfoundation\\request"
BAG_NAMES = frozenset({"query", "request", "cookies", "headers", "attributes", "files", "server"})
BAG_SOURCE_METHODS = frozenset({"get", "all", "keys", "getstring", "filter_raw"})
BAG_SAFE_METHODS = frozenset({"getint", "getboolean", "getalpha", "getalnum", "getdigits", "has", "count",
                              "getiterator"})
REQUEST_SOURCE_METHODS = frozenset({"get", "getcontent", "toarray", "getpayload", "getpathinfo", "getrequesturi",
                                    "geturi", "getquerystring"})
# The current request's own address: built from the trusted Host header and the
# path. Sending a request back to it is not server-side request forgery.
SELF_URL_METHODS = frozenset({"geturi", "getschemeandhttphost", "gethost", "gethttphost", "getbaseurl",
                              "getbasepath", "getpathinfo", "getrequesturi", "geturiforpath", "getscheme", "getport"})
DOCTRINE_SINKS = ("createquery", "createnativequery", "executequery", "executestatement", "executeupdate",
                  "fetchallassociative", "fetchassociative", "fetchone", "fetchfirstcolumn", "fetchallnumeric",
                  "fetchnumeric", "iterateassociative", "query", "exec", "prepare")
DOCTRINE_CLASSES = ("doctrine\\orm\\entitymanagerinterface", "doctrine\\orm\\entitymanager",
                    "doctrine\\dbal\\connection", "doctrine\\persistence\\objectmanager",
                    "doctrine\\orm\\decorator\\entitymanagerdecorator")
HTTP_CLIENT_CLASSES = ("symfony\\contracts\\httpclient\\httpclientinterface",
                       "symfony\\component\\httpclient\\httpclient", "guzzlehttp\\client",
                       "guzzlehttp\\clientinterface", "psr\\http\\client\\clientinterface")
PROCESS_CLASS = "symfony\\component\\process\\process"
RESPONSE_CLASSES = ("symfony\\component\\httpfoundation\\response", "illuminate\\http\\response")
SAFE_RESPONSE_CLASSES = ("symfony\\component\\httpfoundation\\jsonresponse",
                         "symfony\\component\\httpfoundation\\binaryfileresponse",
                         "symfony\\component\\httpfoundation\\redirectresponse",
                         "symfony\\component\\httpfoundation\\streamedresponse")


def route_attribute(node):
    """True when a Method node carries #[Route(...)] (Symfony controller action)."""
    for grp in node.get("attrs") or []:
        attrs = grp if isinstance(grp, list) else getattr(grp, "attrs", None) or [grp]
        for a in attrs:
            name = getattr(a, "name", "") or ""
            if name.lower().rsplit("\\", 1)[-1] in ("route", "get", "post", "put", "patch", "delete"):
                return True
    doc = node.get("doc") or ""
    return "@Route(" in doc


def twig_template_paths(root, name):
    out = []
    for base in ("templates", "app/Resources/views", "src/Resources/views", "resources/views"):
        p = os.path.join(root, base, name)
        if os.path.isfile(p):
            out.append(p)
    return out


_RAW = re.compile(r"\{\{\s*([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*|\[[^\]]*\])*)\s*(\|[^}]*)?\}\}")
_AUTOESC_OFF = re.compile(r"\{%\s*autoescape\s+false\s*%\}(.*?)\{%\s*endautoescape\s*%\}", re.S)


def twig_raw_outputs(path):
    """[(line, var name)] for {{ var|raw }} and output inside {% autoescape false %}."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return []
    out = []
    for m in _RAW.finditer(src):
        filters = m.group(3) or ""
        if re.search(r"\|\s*raw\b", filters):
            out.append((src.count("\n", 0, m.start()) + 1, m.group(1)))
    for blk in _AUTOESC_OFF.finditer(src):
        for m in _RAW.finditer(blk.group(1)):
            if not re.search(r"\|\s*(e|escape)\b", m.group(3) or ""):
                out.append((src.count("\n", 0, blk.start(1) + m.start()) + 1, m.group(1)))
    return out
