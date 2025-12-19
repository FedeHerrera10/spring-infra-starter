package com.fedeherrera.infra.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "google.oauth2.client")
public class GoogleAuthProperties {
    private String id;
    private String secret;

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
}