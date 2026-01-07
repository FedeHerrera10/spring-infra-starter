package com.fedeherrera.infra.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "fedeherrera.infra.jwt")
public class JwtProperties {
    
    @NotBlank(message = "¡Error! Debes configurar 'fedeherrera.infra.jwt.secret-key' en tu .env o application.yml")
    @Pattern(regexp = ".{32,}", 
             message = "La clave secreta debe tener al menos 32 caracteres (256 bits) de longitud")
    private String secretKey;
    
     @Min(value = 1, message = "El tiempo de expiración debe ser mayor a 0")
    private long expiration = 86400000; // 24 horas por defecto
    
    @Min(value = 1, message = "El tiempo de expiración del refresh token debe ser mayor a 0")
    private long refreshExpiration = 604800000; // 7 días por defecto
}