package com.fedeherrera.infra.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@TestConfiguration
public class TestSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Deshabilitas CSRF para facilitar el test
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/verify").permitAll() // Simulas que es público
                        .requestMatchers("/login").permitAll() // Simulas que es público
                        .requestMatchers("/register").permitAll() // Simulas que es público
                        .requestMatchers("/forgot-password").permitAll() // Simulas que es público
                        .requestMatchers("/reset-password").permitAll() // Simulas que es público
                        .requestMatchers("/refresh").permitAll() // Simulas que es público
                        .anyRequest().authenticated());
        return http.build();
    }
}