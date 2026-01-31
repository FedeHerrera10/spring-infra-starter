package com.fedeherrera.infra.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Set;

import com.fedeherrera.infra.dto.AuthProviderEnum;

@MappedSuperclass
@Getter
@Setter
public abstract class BaseUser extends AuditableEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    private String firstName;
    private String lastName;

    private boolean enabled = false;
    private boolean accountNonLocked = true;
    private int failedAttempts;
    private LocalDateTime lockTime;
    private Instant passwordChangedAt;

    @Enumerated(EnumType.STRING)
    private AuthProviderEnum provider = AuthProviderEnum.LOCAL;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

    public void setPasswordChangedAt(Instant passwordChangedAt) {
        this.passwordChangedAt = passwordChangedAt;
    }

    public void setPasswordChangedAtNow() {
        this.passwordChangedAt = Instant.now();
    }
}