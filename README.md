# Spring Boot OAuth 2.0 Demo

# Notes

## Application

- Spring OAuth 2.0 Login page (Authorization code flow with and without PKCE)
- Custom access token exchange via cookie

## keycloak

- `greeters` user group with inherited `GREETER` role mapping for users

### Sample `dev` realm

Users:

`user@example.com` / `password`

Clients:

`public` (**Client authentication: ✅**)

- `Authorization Code` flow with PKCE (interactive) (**Standard flow: ✅**)

`private` (**Client authentication: ❌**)

- `Authorization Code` flow with client secret (interactive) (**Standard flow: ✅**)
- `Client Credentials` flow with client secret (non-interactive) (**Service accounts roles: ✅**)
- `Resource Owner Password` flow with user credentials (non-interactive) (**Direct access grants: ✅**)