package com.fedeherrera.infra;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import com.fedeherrera.infra.config.EmailAutoConfiguration;
import com.fedeherrera.infra.config.GoogleAuthProperties;
import com.fedeherrera.infra.config.JwtProperties;
import com.fedeherrera.infra.config.RateLimitProperties;
import com.fedeherrera.infra.controller.RoleController;
import com.fedeherrera.infra.config.JpaAuditingConfig;
import com.fedeherrera.infra.audit.AuditorAwareConfig;
import com.fedeherrera.infra.config.FilterRegistration;
import com.fedeherrera.infra.config.DefaultSecurityConfig;
import com.fedeherrera.infra.exception.GlobalExceptionHandler;
import com.fedeherrera.infra.service.role.RoleService;

@AutoConfiguration
@Import({ EmailAutoConfiguration.class, JpaAuditingConfig.class, AuditorAwareConfig.class, FilterRegistration.class,
        GlobalExceptionHandler.class, DefaultSecurityConfig.class })
@EnableConfigurationProperties({
        GoogleAuthProperties.class,
        JwtProperties.class,
        RateLimitProperties.class

})
public class ApiAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(org.springframework.security.crypto.password.PasswordEncoder.class)
    public org.springframework.security.crypto.password.PasswordEncoder passwordEncoder() {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean(RoleController.class)
    public RoleController roleController(RoleService roleService) {
        return new RoleController(roleService);
    }
}