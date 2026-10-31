"""Compatibility shim: the URL graph moved into the ``app.graph`` package."""

from .graph.url import MAX_URL_ITERATIONS, URLState, build_url_graph

__all__ = ["MAX_URL_ITERATIONS", "URLState", "build_url_graph"]
