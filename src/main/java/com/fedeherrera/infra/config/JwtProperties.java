package com.fedeherrera.infra.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Validated // Esto activa la validación de las propiedades
@ConfigurationProperties(prefix = "fedeherrera.infra.jwt")
public class JwtProperties {
    
    @NotBlank(message = "¡Error! Debes configurar 'fedeherrera.infra.jwt.secret-key' en tu .env o application.yml")
    private String secretKey; 
    
    private long expiration = 86400000; 
    private long refreshExpiration = 604800000; 
}