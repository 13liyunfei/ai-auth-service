package com.adp.auth.service;

import com.adp.auth.domain.*;
import com.adp.auth.persistence.*;
import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Casbin 策略引擎 —— 数据权限 + 菜单权限的标准化判定层。
 *
 * <p>设计：Casbin 只管"策略判定"（enforce），不管认证/用户实体（仍由 DB 管）。
 * <ul>
 *   <li>策略来源：启动时从现有 role_permission 表 + role 表同步生成
 *       （p = role, dom, obj, act；g = user, role, dom）</li>
 *   <li>多租户：dom 取账号所属团队（当前简化 * 通配域；后续按 user_team 表收敛）</li>
 *   <li>菜单权限：菜单 = 资源 menu:xxx，前端 v-if 与后端 enforce 双保险</li>
 *   <li>超级管理员：显式 policy p, ADMIN, *, *, *（keyMatch2 通配全放行）</li>
 * </ul>
 */
@Service
public class CasbinService {

    private static final Logger log = LoggerFactory.getLogger(CasbinService.class);

    private final Enforcer enforcer;

    private final UserRepository users;
    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final UserRoleRepository userRoles;
    private final RolePermissionRepository rolePermissions;

    public CasbinService(UserRepository users, RoleRepository roles,
                         PermissionRepository permissions,
                         UserRoleRepository userRoles, RolePermissionRepository rolePermissions) {
        this.users = users;
        this.roles = roles;
        this.permissions = permissions;
        this.userRoles = userRoles;
        this.rolePermissions = rolePermissions;
        this.enforcer = buildEnforcer();
        syncPolicies();
        log.info("casbin enforcer ready [policies={} roles={}]",
                enforcer.getPolicy().size(), enforcer.getAllRoles().size());
    }

    private Enforcer buildEnforcer() {
        try {
            InputStream in = new ClassPathResource("casbin/model.conf").getInputStream();
            String modelText = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            Model model = new Model();
            model.loadModelFromText(modelText);
            // 无持久化 adapter：策略完全由 syncPolicies() 从 DB 加载（no-op adapter 防止 loadPolicy NPE）
            return new Enforcer(model, new NoopAdapter());
        } catch (Exception ex) {
            throw new IllegalStateException("casbin model load failed", ex);
        }
    }

    /** no-op Adapter：策略全内存管理（不持久化到文件），由 DB 同步驱动。 */
    static class NoopAdapter implements org.casbin.jcasbin.persist.Adapter {
        public void loadPolicy(Model model) {}
        public void savePolicy(Model model) {}
        public void addPolicy(String sec, String ptype, java.util.List<String> rule) {}
        public void removePolicy(String sec, String ptype, java.util.List<String> rule) {}
        public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {}
    }

    /** 从 DB 同步策略（幂等：先清空再加载）。 */
    public synchronized void syncPolicies() {
        enforcer.clearPolicy();

        // 1) 角色 → 权限点策略（域通配 *：策略对任意 dom 生效；obj = 权限点 code，act = *）
        for (Role role : roles.findAll()) {
            Set<String> permCodes = new LinkedHashSet<>();
            for (RolePermission rp : rolePermissions.findByRoleId(role.getId())) {
                permissions.findById(rp.getPermissionId()).ifPresent(p -> permCodes.add(p.getCode()));
            }
            for (String pc : permCodes) {
                enforcer.addPolicy(role.getCode(), "*", pc, "*");
            }
        }

        // 2) 账号 → 角色（按域通配）
        for (User u : users.findAll()) {
            for (UserRole ur : userRoles.findByUserId(u.getId())) {
                roles.findById(ur.getRoleId()).ifPresent(r -> enforcer.addGroupingPolicy(u.getUsername(), r.getCode(), "*"));
            }
        }

        // 3) 任务资源策略（ABAC 通道：obj=task/123 由 keyMatch2 匹配 task/*；数据归属由业务层兜底）
        //    注意：资源路径用 / 分隔（keyMatch2 把 :xxx 当 REST 参数通配，task:123 会误配 task:read）
        enforcer.addPolicy("ANNOTATOR", "*", "task/*", "read");
        enforcer.addPolicy("ANNOTATOR", "*", "task/*", "transition");
        enforcer.addPolicy("REVIEWER", "*", "task/*", "read");
        enforcer.addPolicy("REVIEWER", "*", "task/*", "transition");
        enforcer.addPolicy("DELIVERY", "*", "task/*", "read");
        enforcer.addPolicy("DELIVERY", "*", "task/*", "deliver");
        enforcer.addPolicy("OPERATOR", "*", "task/*", "*");
        enforcer.addPolicy("ADMIN", "*", "task/*", "*");

        // 注意：不能调用 loadPolicy()（会从 no-op adapter 清空刚加的策略）
        enforcer.buildRoleLinks(); // 重建角色层级索引
        log.info("casbin policies synced from DB [policies={} users={}]",
                enforcer.getPolicy().size(), users.count());
    }

    /**
     * 任务资源级判定（ABAC 通道）：obj 支持 keyMatch2 通配（task/123 命中 task/*）。
     * 数据归属（"是不是我的任务"）由业务层按 assignee 兜底 —— Casbin 不含数据。
     */
    public boolean enforceResource(String username, String resource, String action) {
        return enforce(username, "*", resource, action);
    }

    /**
     * 判定：账号是否可对 dom 域下的 obj 资源执行 act 动作。
     * <pre>
     *   enforce("alice", "*", "quality:report", "*")   → alice 能否看质检报表
     *   enforce("ops",  "*", "project:1", "read")      → ops 能否读项目 1（数据权限，配合 keyMatch2）
     * </pre>
     */
    public boolean enforce(String username, String dom, String obj, String act) {
        try {
            return enforcer.enforce(username, dom, obj, act);
        } catch (Exception ex) {
            log.error("casbin enforce failed [sub={} dom={} obj={} act={}] fail-closed: false",
                    username, dom, obj, act, ex);
            return false; // fail-closed
        }
    }

    /** 账号当前可见的菜单列表（菜单 = 权限点 menu:xxx / 业务权限点映射）。 */
    public List<String> menus(String username) {
        List<String> out = new ArrayList<>();
        for (String perm : permissions.findAll().stream().map(Permission::getCode).toList()) {
            if (perm.startsWith("menu:")) {
                if (enforce(username, "*", perm, "*")) out.add(perm.substring("menu:".length()));
            }
        }
        return out;
    }

    /** 调试：打印全部策略。 */
    public List<List<String>> policies() {
        return enforcer.getPolicy();
    }
}
