-- ============================================================
-- ai-auth-service V1：RBAC 权限中心初始 schema
-- 6 张表：账号 / 角色 / 权限点 / 账号-角色绑定 / 角色-权限绑定 / 令牌
-- 生产 ddl-auto=validate 依赖本迁移建表；dev/test 用 H2 自动建表
-- ============================================================

-- 账号
CREATE TABLE auth_user (
    id            BIGSERIAL PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    display_name  VARCHAR(64),
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMP    NOT NULL DEFAULT now(),
    updated_at    TIMESTAMP
);
CREATE UNIQUE INDEX uk_auth_user_username ON auth_user (username);

-- 角色
CREATE TABLE auth_role (
    id          BIGSERIAL PRIMARY KEY,
    code        VARCHAR(32)  NOT NULL,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP    NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uk_auth_role_code ON auth_role (code);

-- 权限点
CREATE TABLE auth_permission (
    id          BIGSERIAL PRIMARY KEY,
    code        VARCHAR(64)  NOT NULL,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP    NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uk_auth_perm_code ON auth_permission (code);

-- 账号-角色绑定
CREATE TABLE auth_user_role (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT    NOT NULL,
    role_id    BIGINT    NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uk_auth_user_role ON auth_user_role (user_id, role_id);
CREATE INDEX idx_auth_user_role_role ON auth_user_role (role_id);

-- 角色-权限绑定
CREATE TABLE auth_role_permission (
    id            BIGSERIAL PRIMARY KEY,
    role_id       BIGINT    NOT NULL,
    permission_id BIGINT    NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uk_auth_role_perm ON auth_role_permission (role_id, permission_id);
CREATE INDEX idx_auth_role_perm_perm ON auth_role_permission (permission_id);

-- 登录令牌（服务端存储，可吊销）
CREATE TABLE auth_token (
    id         BIGSERIAL PRIMARY KEY,
    token      VARCHAR(64) NOT NULL,
    user_id    BIGINT      NOT NULL,
    expires_at TIMESTAMP   NOT NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT now(),
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX uk_auth_token_value ON auth_token (token);
CREATE INDEX idx_auth_token_user ON auth_token (user_id);
