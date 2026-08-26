package com.adp.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 无状态 JWT 服务（HS256，手写实现零依赖）—— SSO/无状态会话的可选能力：
 * 配置 {@code adp.auth.jwt-secret} 后启用，login 签发 JWT（不再写 Token 表），
 * me/check 从 JWT 解析；未配置则保持 DB Token 模式（默认，向后兼容）。
 */
@Component
public class JwtService {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SecretKeySpec key;
    private final String secret;

    public JwtService(@Value("${adp.auth.jwt-secret:}") String secret) {
        this.secret = secret == null ? "" : secret;
        this.key = this.secret.isBlank() ? null : new SecretKeySpec(sha256(this.secret), "HmacSHA256");
    }

    public boolean enabled() { return key != null; }

    /** 签发 JWT：payload = {sub, iat, exp, jti}。 */
    public String sign(String username, long ttlSeconds) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", username);
        payload.put("iat", System.currentTimeMillis() / 1000);
        payload.put("exp", System.currentTimeMillis() / 1000 + ttlSeconds);
        payload.put("jti", UUID.randomUUID().toString());
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String body = b64(toJson(payload));
        String sig = hmac(header + "." + body);
        return header + "." + body + "." + sig;
    }

    /** 校验并解析 sub；未启用/非法/过期抛 AuthException（复用鉴权语义）。 */
    public String parseUsername(String token) {
        if (key == null) throw new AuthService.AuthException("jwt not enabled");
        if (token == null || token.indexOf('.') < 0) {
            throw new AuthService.AuthException("not a jwt token");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new AuthService.AuthException("invalid jwt");
        String expected = hmac(parts[0] + "." + parts[1]);
        if (!constantTimeEquals(expected, parts[2])) {
            throw new AuthService.AuthException("invalid jwt signature");
        }
        try {
            String json = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<?, ?> payload = mapper.readValue(json, Map.class);
            long exp = ((Number) payload.get("exp")).longValue();
            if (exp * 1000 < System.currentTimeMillis()) {
                throw new AuthService.AuthException("token expired");
            }
            return String.valueOf(payload.get("sub"));
        } catch (AuthService.AuthException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthService.AuthException("invalid jwt payload");
        }
    }

    private String hmac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return b64(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("jwt hmac failed", ex);
        }
    }

    private String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String toJson(Object o) {
        try { return mapper.writeValueAsString(o); }
        catch (Exception ex) { throw new IllegalStateException("jwt payload json failed", ex); }
    }

    private static byte[] sha256(String s) {
        try { return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception ex) { throw new IllegalStateException("sha256 failed", ex); }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int r = 0;
        for (int i = 0; i < a.length(); i++) r |= a.charAt(i) ^ b.charAt(i);
        return r == 0;
    }
}
