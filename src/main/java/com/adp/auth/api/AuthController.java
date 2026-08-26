package com.adp.auth.api;

import com.adp.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * RBAC 对外接口（供数据标注平台等调用方使用）。
 *
 * <p>安全：请求头 {@code X-Auth-Key} 必须等于 {@code adp.auth.api-key}，
 * 防止未授权服务调用本接口（服务间鉴权，与用户 token 是两层）。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService auth;
    private final com.adp.auth.service.CasbinService casbin;

    @Value("${adp.auth.api-key:dev-internal-key}")
    private String apiKey;

    public AuthController(AuthService auth, com.adp.auth.service.CasbinService casbin) {
        this.auth = auth;
        this.casbin = casbin;
    }

    private void requireApiKey(String key) {
        if (apiKey == null || apiKey.isBlank() || !apiKey.equals(key)) {
            throw new AuthService.AuthException("invalid api key");
        }
    }

    /** 登录：username + password → token + 主体（角色/权限）。 */
    @PostMapping("/login")
    public AuthService.LoginResult login(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                         @RequestBody LoginRequest req) {
        requireApiKey(apiKey);
        return auth.login(req.username(), req.password());
    }

    /** 登出：吊销 token。 */
    @PostMapping("/logout")
    public Map<String, Object> logout(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                      @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(apiKey);
        auth.logout(token);
        return Map.of("ok", true);
    }

    /** 解析 token → 当前主体（用户信息 + 角色 + 权限）。 */
    @GetMapping("/me")
    public AuthService.AuthPrincipal me(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                        @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(apiKey);
        return auth.me(token);
    }

    /** 单权限鉴权。 */
    @PostMapping("/check")
    public AuthService.CheckResult check(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                         @RequestHeader("X-Auth-Token") String token,
                                         @RequestBody CheckRequest req) {
        requireApiKey(apiKey);
        return auth.check(token, req.permission());
    }

    /** Casbin 数据权限判定：sub 从 token 解析，判定 {dom, obj, act}。 */
    @PostMapping("/enforce")
    public Map<String, Object> enforce(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                       @RequestHeader("X-Auth-Token") String token,
                                       @RequestBody EnforceRequest req) {
        requireApiKey(apiKey);
        var principal = auth.me(token);
        boolean allowed = casbin.enforce(principal.username(),
                req.dom() == null ? "*" : req.dom(),
                req.obj(), req.act() == null ? "*" : req.act());
        return Map.of("allowed", allowed, "sub", principal.username(), "obj", req.obj());
    }

    /** 任务资源级判定（ABAC 通道）：resource 如 task:123（keyMatch2 通配 task:*）。 */
    @PostMapping("/enforce-resource")
    public Map<String, Object> enforceResource(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                               @RequestHeader("X-Auth-Token") String token,
                                               @RequestBody ResourceRequest req) {
        requireApiKey(apiKey);
        var principal = auth.me(token);
        boolean allowed = casbin.enforceResource(principal.username(), req.resource(), req.action());
        return Map.of("allowed", allowed, "sub", principal.username(), "resource", req.resource(), "action", req.action());
    }

    /** 当前账号可见菜单列表（菜单权限，前端动态渲染双保险）。 */
    @GetMapping("/menus")
    public Map<String, Object> menus(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                     @RequestHeader("X-Auth-Token") String token) {
        requireApiKey(apiKey);
        var principal = auth.me(token);
        return Map.of("menus", casbin.menus(principal.username()));
    }

    /** 批量鉴权（前端按钮可见性预取）。 */
    @PostMapping("/check-batch")
    public Map<String, Boolean> checkBatch(@RequestHeader(value = "X-Auth-Key", required = false) String apiKey,
                                           @RequestHeader("X-Auth-Token") String token,
                                           @RequestBody CheckBatchRequest req) {
        requireApiKey(apiKey);
        return auth.checkBatch(token, req.permissions());
    }

    public record LoginRequest(String username, String password) {}
    public record CheckRequest(String permission) {}
    public record CheckBatchRequest(List<String> permissions) {}
    public record ResourceRequest(String resource, String action) {}
    public record EnforceRequest(String dom, String obj, String act) {}

    @RestControllerAdvice
    static class AuthExceptionHandler {
        @ExceptionHandler(AuthService.AuthException.class)
        public ResponseEntity<Map<String, Object>> handle(AuthService.AuthException ex) {
            String msg = ex.getMessage();
            HttpStatus status = switch (msg) {
                case "invalid api key" -> HttpStatus.UNAUTHORIZED;
                case "invalid credentials", "invalid or expired token",
                     "token expired", "user not found", "account disabled" -> HttpStatus.UNAUTHORIZED;
                default -> HttpStatus.BAD_REQUEST;
            };
            log.warn("auth exception: {} ({} -> {})", msg, status, ex.toString());
            return ResponseEntity.status(status)
                    .body(Map.of("error", "AUTH_FAILED", "message", msg));
        }
    }
}
