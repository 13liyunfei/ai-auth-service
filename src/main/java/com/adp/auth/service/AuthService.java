package com.adp.auth.service;

import com.adp.auth.domain.*;
import com.adp.auth.persistence.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * RBAC 核心服务：
 * <ul>
 *   <li>登录 → 签发服务端 token（DB 存储、可吊销、72h 过期）</li>
 *   <li>me → 解析 token 得到用户 + 角色 + 权限（供调用方前端展示与本地门控）</li>
 *   <li>check → 单权限鉴权（供调用方后端在业务入口调用）</li>
 *   <li>checkAny → 批量鉴权（前端一次性拉取按钮可见性）</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final UserRoleRepository userRoles;
    private final RolePermissionRepository rolePermissions;
    private final TokenRepository tokens;
    private final JwtService jwt;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private final SecureRandom random = new SecureRandom();

    @Value("${adp.auth.token-ttl-hours:72}")
    private long tokenTtlHours;

    public AuthService(UserRepository users, RoleRepository roles, PermissionRepository permissions,
                       UserRoleRepository userRoles, RolePermissionRepository rolePermissions,
                       TokenRepository tokens, JwtService jwt) {
        this.users = users;
        this.roles = roles;
        this.permissions = permissions;
        this.userRoles = userRoles;
        this.rolePermissions = rolePermissions;
        this.tokens = tokens;
        this.jwt = jwt;
    }

    // ---------------- 登录 ----------------

    @Transactional
    public LoginResult login(String username, String rawPassword) {
        User u = users.findByUsername(username)
                .orElseThrow(() -> new AuthException("invalid credentials"));
        if (u.getStatus() != User.Status.ACTIVE) {
            throw new AuthException("account disabled");
        }
        if (!encoder.matches(rawPassword, u.getPasswordHash())) {
            throw new AuthException("invalid credentials");
        }
        Instant expiresAt = Instant.now().plusSeconds(tokenTtlHours * 3600);
        String token;
        if (jwt.enabled()) {
            // JWT 无状态模式：签发即完成，不写 Token 表（SSO 前置）
            token = jwt.sign(username, tokenTtlHours * 3600);
            log.info("login ok (jwt) [user={} roles={}]", u.getUsername(), buildPrincipal(u).roles());
            return new LoginResult(token, expiresAt, buildPrincipal(u));
        }
        token = newToken();
        Token t = new Token();
        t.setToken(token);
        t.setUserId(u.getId());
        t.setExpiresAt(expiresAt);
        tokens.save(t);

        AuthPrincipal principal = buildPrincipal(u);
        log.info("login ok [user={} roles={}]", u.getUsername(), principal.roles());
        return new LoginResult(token, t.getExpiresAt(), principal);
    }

    @Transactional
    public void logout(String token) {
        tokens.findByTokenAndRevokedFalse(token).ifPresent(t -> {
            t.setRevoked(true);
            tokens.save(t);
        });
    }

    // ---------------- 解析 ----------------

    /** 解析 token → 当前主体（用户 + 角色 + 权限）。token 无效/过期/吊销抛 AuthException。 */
    @Transactional(readOnly = true)
    public AuthPrincipal me(String token) {
        // JWT 无状态模式：token 形如 xxx.yyy.zzz → 直接解析（不查 Token 表）
        if (jwt.enabled() && token != null && token.indexOf('.') > 0) {
            String username = jwt.parseUsername(token);
            User u = users.findByUsername(username)
                    .orElseThrow(() -> new AuthException("user not found"));
            if (u.getStatus() != User.Status.ACTIVE) throw new AuthException("account disabled");
            return buildPrincipal(u);
        }
        Token t = tokens.findByTokenAndRevokedFalse(token)
                .orElseThrow(() -> new AuthException("invalid or expired token"));
        if (t.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("token expired");
        }
        User u = users.findById(t.getUserId())
                .orElseThrow(() -> new AuthException("user not found"));
        if (u.getStatus() != User.Status.ACTIVE) {
            throw new AuthException("account disabled");
        }
        return buildPrincipal(u);
    }

    /** 单权限鉴权：token 主体是否拥有 permission。 */
    @Transactional(readOnly = true)
    public CheckResult check(String token, String permission) {
        AuthPrincipal p = me(token);
        boolean allowed = p.permissions().contains(permission);
        log.info("check [user={} permission={} allowed={}]", p.username(), permission, allowed);
        return new CheckResult(allowed, p);
    }

    /** 批量鉴权：一次返回多个权限的判定（前端按钮可见性预取）。 */
    @Transactional(readOnly = true)
    public Map<String, Boolean> checkBatch(String token, List<String> permissionCodes) {
        AuthPrincipal p = me(token);
        Map<String, Boolean> out = new LinkedHashMap<>();
        for (String c : permissionCodes) {
            out.put(c, p.permissions().contains(c));
        }
        return out;
    }

    // ---------------- 内部 ----------------

    private AuthPrincipal buildPrincipal(User u) {
        List<Role> roleList = userRoles.findByUserId(u.getId()).stream()
                .map(ur -> roles.findById(ur.getRoleId()).orElse(null))
                .filter(Objects::nonNull)
                .toList();
        Set<String> roleCodes = new LinkedHashSet<>();
        Set<String> permCodes = new LinkedHashSet<>();
        for (Role r : roleList) {
            roleCodes.add(r.getCode());
            for (RolePermission rp : rolePermissions.findByRoleId(r.getId())) {
                permissions.findById(rp.getPermissionId()).ifPresent(p -> permCodes.add(p.getCode()));
            }
        }
        return new AuthPrincipal(u.getId(), u.getUsername(), u.getDisplayName(), roleCodes, permCodes);
    }

    private String newToken() {
        byte[] b = new byte[24];
        random.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    // ---------------- 记录 & 异常 ----------------

    public record LoginResult(String token, Instant expiresAt, AuthPrincipal principal) {}
    public record CheckResult(boolean allowed, AuthPrincipal principal) {}
    public record AuthPrincipal(Long userId, String username, String displayName,
                                Set<String> roles, Set<String> permissions) {}

    public static class AuthException extends RuntimeException {
        public AuthException(String msg) { super(msg); }
    }
}
