"""Authentication and authorisation.

Responsibilities:
  - JWT token creation and validation
  - User identity extraction from requests
  - RBAC policy enforcement via FastAPI dependencies

Architecture rule: auth concerns must NEVER leak into domain models or
application services.  Services receive an authenticated user identity
(UserContext) as a typed parameter — they do not perform their own auth.
"""
