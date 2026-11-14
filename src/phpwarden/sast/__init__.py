"""phpwarden SAST engine: PHP 8.3 parser (layer 1) and whole-program model (layer 2).

    from phpwarden.sast import parse, Project
    res = parse(open("x.php", encoding="latin-1").read(), "x.php")
    proj = Project.load("/path/to/app")

See README.md in this directory for the data model.
"""
from .parser import parse, parse_file, ParseError, ParseResult  # noqa: F401
from .ast import Node, walk, find, dump  # noqa: F401
