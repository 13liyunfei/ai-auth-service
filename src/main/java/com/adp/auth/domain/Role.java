package com.adp.auth.domain;

import jakarta.persistence.*;
import java.time.Instant;

/** 角色 —— RBAC 中间层：账号绑定角色，角色绑定权限。 */
@Entity
@Table(name = "auth_role", uniqueConstraints = @UniqueConstraint(name = "uk_auth_role_code", columnNames = {"code"}))
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 角色编码：ADMIN / OPERATOR / REVIEWER / ANNOTATOR / DELIVERY */
    @Column(name = "code", nullable = false, length = 32)
    private String code;

    @Column(name = "name", nullable = false, length = 64)
    private String name;

    @Column(name = "description", length = 255)
    private String description;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
