package com.fedeherrera.infra.filter;

import java.time.LocalDateTime;

import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fedeherrera.infra.dto.ErrorResponse;
import com.fedeherrera.infra.service.RateLimitService;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.core.Ordered;
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j // Logger de Lombok
public class RateLimitFilter extends OncePerRequestFilter {

    @Autowired
    private RateLimitService rateLimitService;

    @Autowired
    private ObjectMapper objectMapper; // Para convertir el DTO a JSON

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String path = request.getRequestURI();
        String ip = getClientIp(request);

        // Definimos el límite (ej. 5 para login, 50 para el resto)
        int limit = (path.startsWith("/auth/login")) ? 5 : 50;

        if (rateLimitService.resolveBucket(ip, limit).tryConsume(1)) {
            try {
                filterChain.doFilter(request, response);
            } catch (java.io.IOException e) {
               log.error("Error filter rating limit " + e.getMessage());
            } catch (ServletException e) {
                log.error("Error filter rating limit " + e.getMessage());
            }
        } else {
            // LOG DEL ATAQUE/EXCESO
            log.warn("Rate limit excedido para la IP: {} en el path: {}. Límite: {}", ip, path, limit);
            
            sendCustomError(request, response);
        }
    }

    private void sendCustomError(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ErrorResponse errorDetails = ErrorResponse.builder()
                .timestamp(LocalDateTime.now().toString())
                .status(HttpStatus.SC_TOO_MANY_REQUESTS)
                .error("Too Many Requests")
                .message("Has superado el límite de peticiones. Intenta de nuevo en 1 minuto.")
                .path(request.getRequestURI())
                .build();

        response.setStatus(HttpStatus.SC_TOO_MANY_REQUESTS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        // Escribir el JSON en el body de la respuesta
        try {
            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            
        } catch (java.io.IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf == null) ? request.getRemoteAddr() : xf.split(",")[0];
    }
}