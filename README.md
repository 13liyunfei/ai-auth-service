# ai-auth-service

> [English](README.md) | [中文](README.zh-CN.md)

**RBAC microservice for [ai-data-platform](https://github.com/13liyunfei/ai-data-platform)** — a standalone Java 17 / Spring Boot 3.3 service that provides account → role → permission management, **Casbin policy enforcement** and **stateless JWT sessions**. The platform calls it on every request via `AuthContextFilter` (fail-closed: no token / auth unreachable → 401).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-blue)](pom.xml)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-blue)](pom.xml)

## Highlights

- **Casbin RBAC** — role-permission matrix (`auth_role_permission`), enforced with `enforce` / `enforce-resource` (task-level ABAC via `task/*` wildcards)
- **Stateless JWT sessions** — HS256 signed tokens issued on login (`adp.auth.jwt-secret` opt-in); falls back to DB-token mode when not configured
- **Caller credential** — the platform authenticates itself with `X-Auth-Key` (default `dev-internal-key`, overridable via env)
- **Multi-tenant ready** — team isolation keyed by `X-Team-Id`
- **Admin APIs** — users / roles / permissions CRUD + one-command seed reset
- **Fail-closed integration** — `AuthContextFilter` on the platform rejects any request when auth is down or the token is invalid
- **Full-chain traceId** — isomorphic `TraceContext` + `TraceIdFilter`, echoing `X-Request-Id` from the platform

## Quick Start

Requirements: JDK 17+, Maven 3.8+, PostgreSQL 15+.

```bash
# 1. create the database (schema auto-migrated by Flyway)
createdb ai_auth_service

# 2. run (JWT mode recommended for stateless sessions)
export JAVA_HOME=/path/to/jdk-17
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8101 --adp.auth.jwt-secret=dev-jwt-secret-0123456789abcdef"
# without --adp.auth.jwt-secret it stays in DB-token mode (backward compatible)
```

Seed accounts (password `123456`): `admin` (ADMIN) / `ops` (OPERATOR) / `alice` (ANNOTATOR) / `bob` (REVIEWER) / `delivery` (DELIVERY).

### Integration with ai-data-platform

```yaml
# in ai-data-platform application.yml
adp:
  auth:
    enabled: true
    base-url: ${AUTH_BASE_URL:http://localhost:8101}
    api-key: ${AUTH_API_KEY:dev-internal-key}   # must match the auth service's AUTH_API_KEY
```

- Login: `POST http://localhost:8101/api/auth/login` with `{"username":"admin","password":"123456"}` and header `X-Auth-Key: dev-internal-key` → returns a JWT.
- The platform then forwards every request with `X-Auth-Token: <jwt>`; `AuthContextFilter` resolves account → roles → permissions (fail-closed).

## API

| Method + Path | Purpose | Permission |
|---------------|---------|------------|
| `POST /api/auth/login` | issue JWT (or DB token) | public (X-Auth-Key) |
| `POST /api/auth/logout` | revoke session | auth:manage |
| `GET /api/auth/me` | current account + roles + menus | any authenticated |
| `POST /api/auth/check` | check `{user, perms}` | auth:check |
| `POST /api/auth/check-batch` | batch check multiple users | auth:check |
| `POST /api/auth/enforce` | Casbin enforce (role-based) | auth:manage |
| `POST /api/auth/enforce-resource` | Casbin enforce-resource (ABAC, e.g. `task/read`) | auth:manage |
| `GET /api/auth/menus` | menu tree for current role | any authenticated |
| `GET/POST/PUT/DELETE /api/auth/admin/users` | user CRUD | auth:manage |
| `GET/POST/PUT/DELETE /api/auth/admin/roles` | role CRUD | auth:manage |
| `GET/POST/PUT/DELETE /api/auth/admin/permissions` | permission CRUD | auth:manage |
| `POST /api/auth/admin/reset` | re-seed the default account matrix | auth:manage |

Direct calls to this service use header `X-Auth-Key` (the caller credential); token-based calls from the platform use `X-Auth-Token`.

## Tests

```bash
export JAVA_HOME=/path/to/jdk-17   # ByteBuddy requires < Java 26
mvn -B test                        # 8 tests: login/logout/me/check/enforce/menus/admin CRUD + JWT issue/parse/tamper
```

Tests run on a dedicated real PostgreSQL database (`ai_auth_service_test`, Flyway + ddl-auto=validate).

## License

[MIT](LICENSE) — © 2026 13liyunfei.
