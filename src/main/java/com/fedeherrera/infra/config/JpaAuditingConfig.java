package com.fedeherrera.infra.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing // Esto activa @CreatedDate, @LastModifiedBy, etc.
public class JpaAuditingConfig {
}