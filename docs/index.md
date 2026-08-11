---
layout: home

hero:
  name: Toamaisutaa
  text: Who gets through the gate.
  tagline: トアマイスター - authentication for ASP.NET Core. OIDC bearer validation, optional local password login, and its own EF Core migrations.
  image:
    src: /logo.svg
    alt: Toamaisutaa
  actions:
    - theme: brand
      text: Getting started
      link: /getting-started
    - theme: alt
      text: What is Toamaisutaa?
      link: /intro
    - theme: alt
      text: NuGet
      link: https://www.nuget.org/packages/Toamaisutaa.AspNetCore

features:
  - title: Any OIDC provider
    details: Every endpoint comes from the issuer's discovery document, so Keycloak, Authentik, Pocket ID, Okta and Entra are configuration rather than code.
  - title: Local login when you need it
    details: Username and password sign-in for deployments that cannot run an identity provider, with rotating refresh tokens and lockout.
  - title: TOTP, without a TOTP library
    details: Two-factor authentication with recovery codes, an opaque single-use challenge that cannot be presented as a bearer token, and secrets encrypted at rest. No new dependency.
  - title: Bring your own database
    details: Postgres, SQLite, SQL Server and MySQL migrations ship with the package, or apply the entity configurations to a DbContext you already have.
  - title: Optional user table
    details: Provisioning is opt-in. The package works perfectly well when the identity provider owns every user and you store nothing.
---
