package com.adp.auth.service;

import com.adp.auth.domain.*;
import com.adp.auth.persistence.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 种子数据：5 角色 + 权限点 + 角色权限矩阵 + 演示账号。
 *
 * <p>幂等：角色/权限按 code 存在即跳过；账号按 username 存在即跳过。
 */
@Component
public class AuthSeedData implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AuthSeedData.class);

    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final UserRoleRepository userRoles;
    private final RolePermissionRepository rolePermissions;
    private final UserRepository users;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    /** 角色 → 权限点 矩阵（与标注平台状态机门控一一对应）。 */
    private static final Map<String, String[]> ROLE_PERMISSIONS = new LinkedHashMap<>() {{
        put("ADMIN", new String[]{
                "project:create", "project:manage", "task:import", "task:assign",
                "task:read", "task:transition", "task:quality-check", "task:approve", "task:reject",
                "task:deliver", "quality:report", "quality:rules", "al:suggest",
                "auth:manage", "auth:role-assign"});
        put("OPERATOR", new String[]{
                "project:create", "task:import", "task:assign", "task:read", "task:transition",
                "task:quality-check", "task:approve", "task:reject",
                "quality:report", "quality:rules", "al:suggest"});
        put("REVIEWER", new String[]{
                "task:read", "task:transition", "task:quality-check", "task:reject",
                "quality:report", "al:suggest"});
        put("ANNOTATOR", new String[]{
                "task:read", "task:transition", "task:submit"});
        put("DELIVERY", new String[]{
                "task:read", "task:deliver", "task:transition"});
    }};

    public AuthSeedData(RoleRepository roles, PermissionRepository permissions,
                        UserRoleRepository userRoles, RolePermissionRepository rolePermissions,
                        UserRepository users) {
        this.roles = roles;
        this.permissions = permissions;
        this.userRoles = userRoles;
        this.rolePermissions = rolePermissions;
        this.users = users;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seed();
    }

    /** 重置入口（admin 调用）：清空关联 + 重新按默认 seed 矩阵绑定。 */
    @Transactional
    public void reSeed() {
        // 清空所有 user_role / role_permission 关联（保留账号、角色、权限点本身）
        for (User u : users.findAll()) {
            userRoles.deleteByUserId(u.getId());
            userRoles.flush();
        }
        for (Role r : roles.findAll()) {
            rolePermissions.deleteByRoleId(r.getId());
            rolePermissions.flush();
        }
        seed();
        log.info("admin reset: re-seed done [users={} roles={} perms={}]",
                users.count(), roles.count(), permissions.count());
    }

    private void seed() {
        Map<String, Permission> permByCode = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> e : ROLE_PERMISSIONS.entrySet()) {
            for (String code : e.getValue()) {
                permByCode.computeIfAbsent(code, c -> {
                    Permission p = new Permission();
                    p.setCode(c);
                    p.setName(c);
                    p.setDescription("permission " + c);
                    return permissions.findByCode(c).orElseGet(() -> permissions.save(p));
                });
            }
        }

        Map<String, Role> roleByCode = new LinkedHashMap<>();
        for (String code : ROLE_PERMISSIONS.keySet()) {
            Role r = roles.findByCode(code).orElseGet(() -> {
                Role nr = new Role();
                nr.setCode(code);
                nr.setName(code);
                nr.setDescription("role " + code);
                return roles.save(nr);
            });
            roleByCode.put(code, r);
            // 绑定角色 → 权限
            for (String pc : ROLE_PERMISSIONS.get(code)) {
                Permission p = permByCode.get(pc);
                boolean bound = rolePermissions.findByRoleId(r.getId()).stream()
                        .anyMatch(rp -> rp.getPermissionId().equals(p.getId()));
                if (!bound) {
                    rolePermissions.save(new RolePermission(r.getId(), p.getId()));
                }
            }
        }

        // 演示账号（密码统一 123456）：alice 标注员 / bob 审核员 / ops 运营 / delivery 交付 / admin 管理员
        createUser("alice", "Alice 标注员", new String[]{"ANNOTATOR"});
        createUser("bob", "Bob 审核员", new String[]{"REVIEWER"});
        createUser("ops", "Ops 运营", new String[]{"OPERATOR"});
        createUser("delivery", "Delivery 交付", new String[]{"DELIVERY"});
        createUser("admin", "Admin 管理员", new String[]{"ADMIN"});
        // 复合角色示例：ops 同时可审（内部小型团队常见）
        createUser("ops-reviewer", "Ops+Reviewer", new String[]{"OPERATOR", "REVIEWER"});

        log.info("auth seed done [roles={} permissions={} users={}]",
                roleByCode.size(), permByCode.size(), users.count());
    }

    private void createUser(String username, String displayName, String[] roleCodes) {
        users.findByUsername(username).ifPresentOrElse(u -> {
            // 已有则补齐角色绑定
            for (String rc : roleCodes) {
                roles.findByCode(rc).ifPresent(r -> {
                    boolean bound = userRoles.findByUserId(u.getId()).stream()
                            .anyMatch(ur -> ur.getRoleId().equals(r.getId()));
                    if (!bound) userRoles.save(new UserRole(u.getId(), r.getId()));
                });
            }
        }, () -> {
            User u = new User();
            u.setUsername(username);
            u.setDisplayName(displayName);
            u.setPasswordHash(encoder.encode("123456"));
            users.save(u);
            for (String rc : roleCodes) {
                roles.findByCode(rc).ifPresent(r -> userRoles.save(new UserRole(u.getId(), r.getId())));
            }
            log.info("  seed user {} [{}]", username, String.join(",", roleCodes));
        });
    }
}
