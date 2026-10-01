"""FastAPI router package.

Architecture rule: routers contain ONLY HTTP concerns (request parsing,
response serialisation, dependency injection).  All business logic lives
in application services under intriqo.services.
"""
