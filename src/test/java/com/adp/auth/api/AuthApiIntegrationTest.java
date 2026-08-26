package com.adp.auth.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * RBAC 集成测试：
 * - 登录（alice/123456）→ token
 * - me：alice 只有 ANNOTATOR 角色 + task:transition/task:submit 权限
 * - check：alice 无 task:approve；ops 有 task:approve
 * - 错误密码 / 无效 token / 错误 api-key → 401
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthApiIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private static final String KEY = "dev-internal-key";

    private String login(String username, String password) throws Exception {
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .header("X-Auth-Key", KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return json.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    @Order(1)
    void loginAndMe() throws Exception {
        String token = login("alice", "123456");
        assertFalse(token.isBlank());

        mvc.perform(get("/api/auth/me")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[0]").value("ANNOTATOR"))
                .andExpect(jsonPath("$.permissions", org.hamcrest.Matchers.hasItems("task:transition", "task:submit")));
    }

    @Test
    @Order(2)
    void roleGatesPermissions() throws Exception {
        // alice（ANNOTATOR）不能 approve
        String alice = login("alice", "123456");
        mvc.perform(post("/api/auth/check")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", alice)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permission\":\"task:approve\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false));

        // ops（OPERATOR）可以 approve / import / assign
        String ops = login("ops", "123456");
        mvc.perform(post("/api/auth/check")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", ops)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permission\":\"task:approve\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true));
    }

    @Test
    @Order(3)
    void batchCheck() throws Exception {
        String token = login("bob", "123456");
        mvc.perform(post("/api/auth/check-batch")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"permissions\":[\"task:quality-check\",\"task:approve\",\"task:deliver\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$['task:quality-check']").value(true))
                .andExpect(jsonPath("$['task:approve']").value(false))
                .andExpect(jsonPath("$['task:deliver']").value(false));
    }

    @Test
    @Order(4)
    void rejectInvalidCredentials() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .header("X-Auth-Key", KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/api/auth/me")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", "invalid-token"))
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/api/auth/me")
                        .header("X-Auth-Key", "wrong-key")
                        .header("X-Auth-Token", "whatever"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    void logoutRevokesToken() throws Exception {
        String token = login("alice", "123456");
        mvc.perform(post("/api/auth/logout")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", token))
                .andExpect(status().isOk());
        mvc.perform(get("/api/auth/me")
                        .header("X-Auth-Key", KEY)
                        .header("X-Auth-Token", token))
                .andExpect(status().isUnauthorized());
    }
}
