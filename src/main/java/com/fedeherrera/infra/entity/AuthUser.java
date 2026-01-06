package com.fedeherrera.infra.entity;

import java.time.Instant;

public interface AuthUser {
    Long getId();
    Instant getPasswordChangedAt();
}
