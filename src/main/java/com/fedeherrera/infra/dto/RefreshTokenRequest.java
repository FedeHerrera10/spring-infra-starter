package com.fedeherrera.infra.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class RefreshTokenRequest {
    @NotBlank(message = "El refresh token es obligatorio")
    private String refreshToken;
    
}
