"""Framework and library models for the AST taint engine (layer 4).

Each module is declarative: sources, sinks, sanitizers, propagators and entry
points for one ecosystem. taint.py interprets them.
"""
from . import laravel, php_builtins, symfony, wordpress  # noqa: F401
