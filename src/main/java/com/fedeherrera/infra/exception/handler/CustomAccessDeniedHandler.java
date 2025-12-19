package com.fedeherrera.infra.exception.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fedeherrera.infra.dto.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, 
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // Status 403


        // 🔹 Logueamos el intento de acceso no autorizado
        // Usamos .warn porque es una advertencia de seguridad
        log.warn("Acceso no autorizado detectado: IP={}, Path={}, Error={}", 
                 request.getRemoteAddr(), 
                 request.getServletPath(), 
                 accessDeniedException.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now().toString())
                .status(HttpServletResponse.SC_FORBIDDEN)
                .error("Forbidden")
                .message("No tienes los permisos (roles) necesarios para acceder a este recurso")
                .path(request.getServletPath())
                .build();

        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}