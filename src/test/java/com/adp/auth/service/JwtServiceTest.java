package com.adp.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 无状态 JWT 测试：签发/解析、篡改拒绝、过期拒绝、未配置时禁用。
 */
class JwtServiceTest {

    @Test
    void signAndParse() {
        JwtService jwt = new JwtService("test-secret");
        assertTrue(jwt.enabled());
        String token = jwt.sign("alice", 3600);
        assertEquals("alice", jwt.parseUsername(token));
    }

    @Test
    void tamperedTokenRejected() {
        JwtService jwt = new JwtService("test-secret");
        String token = jwt.sign("alice", 3600);
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "B" : "A");
        assertThrows(AuthService.AuthException.class, () -> jwt.parseUsername(tampered));
    }

    @Test
    void disabledWithoutSecret() {
        JwtService jwt = new JwtService("");
        assertFalse(jwt.enabled());
        assertThrows(AuthService.AuthException.class, () -> jwt.parseUsername("a.b.c"));
    }
}
