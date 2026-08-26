# ai-auth-service

> [English](README.md) | [中文](README.zh-CN.md)

**配合 [ai-data-platform](https://gitee.com/liyunfei2030/ai-data-platform) 的 RBAC 权限微服务** —— 独立的 Java 17 / Spring Boot 3.3 服务，提供 账号 → 角色 → 权限 管理、**Casbin 策略执行** 与 **无状态 JWT 会话**。平台侧每个请求经 `AuthContextFilter` 调用本服务鉴权（fail-closed：无 token / auth 不可达 → 401）。

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-blue)](pom.xml)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-blue)](pom.xml)

## 核心能力

- **Casbin RBAC** —— 角色-权限矩阵（`auth_role_permission`），`enforce` / `enforce-resource` 双通道（任务级 ABAC，`task/*` 通配）
- **无状态 JWT 会话** —— 登录签发 HS256 token（`adp.auth.jwt-secret` 可选）；未配置回退 DB Token 模式（向后兼容）
- **调用方凭据** —— 平台侧用 `X-Auth-Key`（默认 `dev-internal-key`，环境变量可覆盖）自证身份
- **多租户就绪** —— 按 `X-Team-Id` 隔离团队数据
- **后管 API** —— 用户/角色/权限 CRUD + 一键重置默认账号矩阵
- **Fail-closed 集成** —— 平台 `AuthContextFilter`：auth 不可达或 token 非法 → 401
- **全链路 traceId** —— 同构 `TraceContext` + `TraceIdFilter`，回传平台 `X-Request-Id`

## 快速开始

要求：JDK 17+、Maven 3.8+、PostgreSQL 15+。

```bash
# 1. 建库（schema 由 Flyway 自动迁移）
createdb ai_auth_service

# 2. 启动（推荐 JWT 无状态模式）
export JAVA_HOME=/path/to/jdk-17
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8101 --adp.auth.jwt-secret=dev-jwt-secret-0123456789abcdef"
# 不带 --adp.auth.jwt-secret 则保持 DB Token 模式（向后兼容）
```

种子账号（密码均为 `123456`）：`admin`（ADMIN）/ `ops`（OPERATOR）/ `alice`（ANNOTATOR）/ `bob`（REVIEWER）/ `delivery`（DELIVERY）。

### 与 ai-data-platform 对接

```yaml
# 在 ai-data-platform 的 application.yml 中
adp:
  auth:
    enabled: true
    base-url: ${AUTH_BASE_URL:http://localhost:8101}
    api-key: ${AUTH_API_KEY:dev-internal-key}   # 需与本服务 AUTH_API_KEY 一致
```

- 登录：`POST http://localhost:8101/api/auth/login`，body `{"username":"admin","password":"123456"}`，请求头 `X-Auth-Key: dev-internal-key` → 返回 JWT。
- 平台此后每个请求带 `X-Auth-Token: <jwt>`；`AuthContextFilter` 解析 账号 → 角色 → 权限（fail-closed）。

## API

| Method + Path | 作用 | 权限 |
|---------------|------|------|
| `POST /api/auth/login` | 签发 JWT（或 DB token） | 公开（X-Auth-Key） |
| `POST /api/auth/logout` | 注销会话 | auth:manage |
| `GET /api/auth/me` | 当前账号 + 角色 + 菜单 | 任意已登录 |
| `POST /api/auth/check` | 校验 `{user, perms}` | auth:check |
| `POST /api/auth/check-batch` | 批量校验多用户 | auth:check |
| `POST /api/auth/enforce` | Casbin 角色策略执行 | auth:manage |
| `POST /api/auth/enforce-resource` | Casbin 资源级 ABAC（如 `task/read`） | auth:manage |
| `GET /api/auth/menus` | 当前角色菜单树 | 任意已登录 |
| `GET/POST/PUT/DELETE /api/auth/admin/users` | 用户 CRUD | auth:manage |
| `GET/POST/PUT/DELETE /api/auth/admin/roles` | 角色 CRUD | auth:manage |
| `GET/POST/PUT/DELETE /api/auth/admin/permissions` | 权限 CRUD | auth:manage |
| `POST /api/auth/admin/reset` | 重置默认账号矩阵 | auth:manage |

直连本服务用 `X-Auth-Key`（调用方凭据）；平台经 token 访问用 `X-Auth-Token`。

## 测试

```bash
export JAVA_HOME=/path/to/jdk-17   # ByteBuddy 需 < Java 26
mvn -B test                        # 8 个测试：登录/登出/me/check/enforce/menus/后管 CRUD + JWT 签发/解析/防篡改
```

测试跑在独立真实 PostgreSQL 测试库（`ai_auth_service_test`，Flyway + ddl-auto=validate）。

## License

[MIT](LICENSE) — © 2026 liyunfei2030.
