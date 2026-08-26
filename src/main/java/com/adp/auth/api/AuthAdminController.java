package com.adp.auth.api;

import com.adp.auth.domain.*;
import com.adp.auth.persistence.*;
import com.adp.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 权限管理 API（仅管理员使用，前端"权限管理"页数据源）。
 *
 * <p>安全：请求头 {@code X-Auth-Key} 必须匹配 adp.auth.api-key（服务间），
 * 且 {@code X-Auth-Token} 对应的账号必须拥有 ADMIN 角色（调用方平台侧已校验 auth:manage）。
 */
@RestController
@RequestMapping("/api/auth/admin")
public class AuthAdminController {

    private static final Logger log = LoggerFactory.getLogger(AuthAdminController.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final UserRoleRepository userRoles;
    private final RolePermissionRepository rolePermissions;
    private final TokenRepository tokens;
    private final AuthService auth;
    private final com.adp.auth.service.AuthSeedData seedData;
    private final com.adp.auth.service.CasbinService casbin;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Value("${adp.auth.api-key:dev-internal-key}")
    private String apiKey;

    public AuthAdminController(UserRepository users, RoleRepository roles,
                               PermissionRepository permissions,
                               UserRoleRepository userRoles, RolePermissionRepository rolePermissions,
                               TokenRepository tokens, AuthService auth,
                               com.adp.auth.service.AuthSeedData seedData,
                               com.adp.auth.service.CasbinService casbin) {
        this.users = users;
        this.roles = roles;
        this.permissions = permissions;
        this.userRoles = userRoles;
        this.rolePermissions = rolePermissions;
        this.tokens = tokens;
        this.auth = auth;
        this.seedData = seedData;
        this.casbin = casbin;
    }

    private void requireApiKey(String key) {
        if (apiKey == null || apiKey.isBlank() || !apiKey.equals(key)) {
            throw new AuthService.AuthException("invalid api key");
        }
    }

    private void requireAdminToken(String token) {
        AuthService.AuthPrincipal p = auth.me(token);
        if (!p.roles().contains("ADMIN")) {
            throw new AuthService.AuthException("admin required");
        }
    }

    // ---------------- 查询 ----------------

    /** 用户列表（含各自角色 code）。 */
    @GetMapping("/users")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> users(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                           @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(key);
        requireAdminToken(token);
        return users.findAll().stream().map(u -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", u.getId());
            m.put("username", u.getUsername());
            m.put("displayName", u.getDisplayName());
            m.put("status", u.getStatus().name());
            m.put("roles", userRoles.findByUserId(u.getId()).stream()
                    .map(ur -> roles.findById(ur.getRoleId()).map(Role::getCode).orElse(null))
                    .filter(Objects::nonNull).toList());
            return m;
        }).toList();
    }

    /** 角色列表（含各自权限 code）。 */
    @GetMapping("/roles")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> roles(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                           @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(key);
        requireAdminToken(token);
        return roles.findAll().stream().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.getId());
            m.put("code", r.getCode());
            m.put("name", r.getName());
            m.put("description", r.getDescription());
            m.put("permissions", rolePermissions.findByRoleId(r.getId()).stream()
                    .map(rp -> permissions.findById(rp.getPermissionId()).map(Permission::getCode).orElse(null))
                    .filter(Objects::nonNull).toList());
            return m;
        }).toList();
    }

    /** 全部权限点（角色编辑时的候选列表）。 */
    @GetMapping("/permissions")
    @Transactional(readOnly = true)
    public List<Permission> permissions(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                        @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(key);
        requireAdminToken(token);
        return permissions.findAll();
    }

    // ---------------- 用户管理 ----------------

    /** 创建用户。 */
    @PostMapping("/users")
    @Transactional
    public Map<String, Object> createUser(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                          @RequestHeader("X-Auth-Token") String token,
                                          @RequestBody CreateUserReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        if (users.existsByUsername(req.username())) {
            throw new AuthService.AuthException("username already exists");
        }
        User u = new User();
        u.setUsername(req.username());
        u.setDisplayName(req.displayName());
        u.setPasswordHash(encoder.encode(req.password()));
        users.save(u);
        if (req.roles() != null) {
            for (String rc : req.roles()) {
                roles.findByCode(rc).ifPresent(r -> userRoles.save(new UserRole(u.getId(), r.getId())));
            }
        }
        log.info("admin create user [{}] roles={}", req.username(), req.roles());
        return Map.of("id", u.getId(), "username", u.getUsername(), "ok", true);
    }

    /** 绑定/解绑用户角色（全量覆盖）。 */
    @PutMapping("/users/{userId}/roles")
    @Transactional
    public Map<String, Object> bindUserRoles(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                             @RequestHeader("X-Auth-Token") String token,
                                             @PathVariable Long userId,
                                             @RequestBody BindRolesReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        User u = users.findById(userId).orElseThrow(() -> new AuthService.AuthException("user not found"));
        userRoles.deleteByUserId(userId);
        userRoles.flush(); // 先落库删除，避免与新插入撞唯一约束（uk_auth_user_role）
        if (req.roles() != null) {
            for (String rc : req.roles()) {
                roles.findByCode(rc).ifPresent(r -> userRoles.save(new UserRole(userId, r.getId())));
            }
        }
        tokens.deleteByUserId(userId); // 强制重新登录生效
        log.info("admin bind user[{}] roles={}", u.getUsername(), req.roles());
        return Map.of("ok", true, "userId", userId);
    }

    /** 重置密码。 */
    @PutMapping("/users/{userId}/password")
    @Transactional
    public Map<String, Object> resetPassword(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                             @RequestHeader("X-Auth-Token") String token,
                                             @PathVariable Long userId,
                                             @RequestBody ResetPwdReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        User u = users.findById(userId).orElseThrow(() -> new AuthService.AuthException("user not found"));
        u.setPasswordHash(encoder.encode(req.password()));
        users.save(u);
        tokens.deleteByUserId(userId);
        log.info("admin reset password [{}]", u.getUsername());
        return Map.of("ok", true);
    }

    /** 启用/禁用账号。 */
    @PutMapping("/users/{userId}/status")
    @Transactional
    public Map<String, Object> setStatus(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                         @RequestHeader("X-Auth-Token") String token,
                                         @PathVariable Long userId,
                                         @RequestBody StatusReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        User u = users.findById(userId).orElseThrow(() -> new AuthService.AuthException("user not found"));
        u.setStatus(User.Status.valueOf(req.status()));
        users.save(u);
        tokens.deleteByUserId(userId);
        log.info("admin set user[{}] status={}", u.getUsername(), req.status());
        return Map.of("ok", true);
    }

    // ---------------- 角色管理 ----------------

    /** 绑定/解绑角色权限（全量覆盖）。 */
    @PutMapping("/roles/{roleId}/permissions")
    @Transactional
    public Map<String, Object> bindRolePermissions(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                                   @RequestHeader("X-Auth-Token") String token,
                                                   @PathVariable Long roleId,
                                                   @RequestBody BindPermsReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        Role r = roles.findById(roleId).orElseThrow(() -> new AuthService.AuthException("role not found"));
        rolePermissions.deleteByRoleId(roleId);
        rolePermissions.flush(); // 先落库删除，避免与新插入撞唯一约束（uk_auth_role_perm）
        if (req.permissions() != null) {
            for (String pc : req.permissions()) {
                permissions.findByCode(pc).ifPresent(p -> rolePermissions.save(new RolePermission(roleId, p.getId())));
            }
        }
        casbin.syncPolicies(); // 同步 Casbin 策略，立即生效
        log.info("admin bind role[{}] permissions={}", r.getCode(), req.permissions());
        return Map.of("ok", true, "roleId", roleId);
    }

    /** 新建角色。 */
    @PostMapping("/roles")
    @Transactional
    public Map<String, Object> createRole(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                          @RequestHeader("X-Auth-Token") String token,
                                          @RequestBody CreateRoleReq req) {
        requireApiKey(key);
        requireAdminToken(token);
        if (roles.findByCode(req.code()).isPresent()) {
            throw new AuthService.AuthException("role code already exists");
        }
        Role r = new Role();
        r.setCode(req.code());
        r.setName(req.name());
        r.setDescription(req.description());
        roles.save(r);
        if (req.permissions() != null) {
            for (String pc : req.permissions()) {
                permissions.findByCode(pc).ifPresent(p -> rolePermissions.save(new RolePermission(r.getId(), p.getId())));
            }
        }
        casbin.syncPolicies(); // 同步 Casbin 策略
        log.info("admin create role [{}]", req.code());
        return Map.of("id", r.getId(), "code", r.getCode(), "ok", true);
    }

    public record CreateUserReq(String username, String displayName, String password, List<String> roles) {}
    public record BindRolesReq(List<String> roles) {}
    public record BindPermsReq(List<String> permissions) {}
    public record ResetPwdReq(String password) {}
    public record StatusReq(String status) {}
    public record CreateRoleReq(String code, String name, String description, List<String> permissions) {}

    /** 危险操作：重置为初始 seed（清空关联 + 按默认矩阵重新绑定；账号/角色/权限点本身保留）。 */
    @PostMapping("/reset")
    @Transactional
    public Map<String, Object> reset(@RequestHeader(value = "X-Auth-Key", required = false) String key,
                                      @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(key);
        requireAdminToken(token);
        seedData.reSeed();
        tokens.deleteAll(); // 强制所有人重新登录
        casbin.syncPolicies(); // 同步 Casbin 策略
        log.info("admin reset: all tokens revoked, seed re-applied, casbin synced");
        return Map.of("ok", true, "message", "all user-role/role-permission bindings reset to seed default; all users must re-login");
    }
}
