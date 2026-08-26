# 权限框架选型评估与落地（RBAC + 数据权限 + 菜单权限）

> 背景：AI 训练数据生产平台数据敏感性高，需要严格的账号-角色-数据权限-菜单权限管控。
> 现状：auth-service 已有自研 RBAC（User/Role/Permission/UserRole/RolePermission/Token + me() 权限集合），
> 标注平台用 AuthClient + requirePermission 做接口级门控。缺口：①菜单/模块按权限展示；②任务级数据隔离；③策略标准化。
> 目标：引入成熟开源权限框架，补齐数据权限 + 菜单权限的标准化管控。

## 一、候选框架横评（2026-08 调研）

| 框架 | 定位 | RBAC | 数据权限 | 菜单权限 | 多租户 | 认证 | 上手成本 | 结论 |
|------|------|------|----------|----------|--------|------|----------|------|
| **Casbin (jCasbin)** | 策略引擎（ACL/RBAC/ABAC/RESTful） | ✅ 内置 | ✅ 策略模型+ABAC | ✅ 官方 menu-permissions 文档 | ✅ RBAC with domains | ❌ 不管认证（与我们互补） | 中 | ✅ **选用** |
| Sa-Token | 国产轻量认证鉴权 | ✅ 需自建 | ❌ 需自建 | ❌ 需自建 | ❌ 需自建 | ✅ 内置 | 低 | 认证替代品，数据权限缺口 |
| Spring Security | Spring 生态标准安全 | ⚠️ 需自建 | ❌ 需自建 | ❌ 需自建 | ❌ 需自建 | ✅ | 高 | 重，且要推翻现有 token 体系 |
| Keycloak | 企业级 IDP/SSO | ✅ | ⚠️ 部分 | ✅ | ✅ | ✅ | 很高 | 太重，适合对外 SSO，不适合内部服务 |

### 选型理由
1. **数据权限是硬需求**：Casbin 的策略模型（`sub, dom, obj, act`）天然支持"任务级/项目级"授权——
   如 `p, REVIEWER, project:1, task, read` 表示 REVIEWER 可读项目 1 的任务，配合 `keyMatch` 支持 `/task/123` 通配。
2. **菜单权限官方支持**：Casbin 官方文档提供 menu-permissions 模型（角色-菜单-层级 g2），
   正是"无权限的模块不展示"的标准解法。
3. **多租户对齐**：Casbin 的 RBAC with domains 模型与我们的 teamId 隔离（__global__/team-a/team-b）天然契合。
4. **不推翻现有体系**：Casbin 不管认证（不做 token/密码），我们保留现有 token 体系 + me() 权限集合，
   Casbin 只做**策略判定层**（enforce），两者互补。
5. **明确边界**：Casbin 官方明确"不管理用户/角色实体"——用户/角色仍由我们 DB 管，策略从现有
   role_permission 表同步生成，管理 API 改动角色时同步 addPolicy/removePolicy。

## 二、落地架构

```
┌─────────────┐   X-Auth-Token    ┌─────────────────┐   X-Auth-Key   ┌────────────────────────┐
│ 前端工作台    │ ───────────────▶ │ ai-data-platform  │ ─────────────▶ │ ai-auth-service        │
│ (菜单按权限v-if)│                  │ AuthClient        │                │ ┌────────────────────┐ │
└─────────────┘                  │ requirePermission  │                │ │ jCasbin Enforcer     │ │
                                 └─────────────────┘                │ │ RBAC + Domains + ABAC│ │
                                                                      │ │ policy 从 role_perm  │ │
                                                                      │ │ 表同步                │ │
                                                                      │ └────────────────────┘ │
                                                                      └────────────────────────┘
```

### 新增 API（auth-service）
| 接口 | 说明 | 用途 |
|------|------|------|
| `POST /api/auth/enforce` | `{dom, obj, act}` → `{allowed}` | **数据权限**判定（sub 从 token 解析） |
| `GET /api/auth/menus` | → 当前用户可见菜单列表 | **菜单权限**（前端动态渲染侧边栏） |
| `POST /api/auth/admin/policy` | 增删策略（ADMIN） | 细粒度策略管理 |

### 菜单权限双保险
- **前端**：`me().permissions` 过滤（`hasPerm('quality:report')`）→ 无权限菜单不渲染（已落地）
- **后端**：菜单资源 `menu:quality` 也进 Casbin policy → `/api/auth/menus` 二次确认（防止前端被绕过）

### 数据权限演进路径
1. **阶段 1（已落地）**：接口级权限 requirePermission + 任务级数据隔离（board 按 assigneeId 过滤）
2. **阶段 2（本次引入）**：Casbin enforce 标准化判定（sub+dom+obj+act），
   项目级策略 `p, role, project:{id}, task, read` 覆盖"谁能看哪个项目"（数据敏感项目精确管控）
3. **阶段 3（后续）**：任务级动态策略 + ABAC 属性规则（如 `task.owner == r.sub` 资源归属判定）

## 三、落地记录
- [x] 前端菜单按 me().permissions 过滤（App.vue hasPerm）
- [x] auth-service 引入 jcasbin（model.conf + policy 同步 + /api/auth/enforce + /api/auth/menus）
- [ ] 标注平台关键读端点渐进迁移到 enforce（report/al/rules 已用 requirePermission，等价）
- [ ] 项目级策略管理 UI（权限管理页"数据权限"tab）
