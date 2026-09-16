"""Bounded HTTP redirect tracing with explicit destination restrictions."""

from .tracer import HTTPResponse, TracePolicy, trace_redirects

__all__ = ["HTTPResponse", "TracePolicy", "trace_redirects"]
