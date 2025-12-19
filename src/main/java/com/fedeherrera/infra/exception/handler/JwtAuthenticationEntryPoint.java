package com.fedeherrera.infra.exception.handler;

import java.io.IOException;
import java.time.LocalDateTime;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fedeherrera.infra.dto.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;


@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, 
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        
// 🔹 Logueamos el intento de acceso no autorizado
        // Usamos .warn porque es una advertencia de seguridad
        log.warn("Acceso no autorizado detectado: IP={}, Path={}, Error={}", 
                 request.getRemoteAddr(), 
                 request.getServletPath(), 
                 authException.getMessage());

        // 1. Definimos que la respuesta será JSON y con status 401 (Unauthorized)
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // 2. Creamos el cuerpo del error
        ErrorResponse error = ErrorResponse.builder()
            .timestamp(LocalDateTime.now().toString())
            .status(HttpServletResponse.SC_UNAUTHORIZED)
            .error("Unauthorized")
            .message("Token inválido, expirado o no proporcionado")
            .path(request.getServletPath())
            .build();

            new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}