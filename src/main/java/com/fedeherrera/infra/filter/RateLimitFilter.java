package com.fedeherrera.infra.filter;

import java.time.LocalDateTime;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fedeherrera.infra.dto.ErrorResponse;
import com.fedeherrera.infra.service.RateLimitService;

import lombok.extern.slf4j.Slf4j;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    @Autowired
    private RateLimitService rateLimitService;

    private final ObjectMapper objectMapper;

    /**
     * Constructor con inyección opcional.
     * Si Spring aún no ha creado el bean de ObjectMapper (debido a la alta prioridad del filtro),
     * creamos uno manualmente para evitar que la aplicación falle al arrancar.
     */
    public RateLimitFilter(@Autowired(required = false) ObjectMapper objectMapper) {
        if (objectMapper != null) {
            this.objectMapper = objectMapper;
            log.info("RateLimitFilter: Usando ObjectMapper inyectado por Spring.");
        } else {
            this.objectMapper = new ObjectMapper();
            // Registramos el módulo para que soporte LocalDateTime si fuera necesario
            this.objectMapper.registerModule(new JavaTimeModule());
            log.warn("RateLimitFilter: ObjectMapper no encontrado en el contexto, se creó una instancia manual.");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, java.io.IOException {
        
        String path = request.getRequestURI();
        String ip = getClientIp(request);

        // Definimos el límite (ej. 5 para login, 50 para el resto)
        int limit = (path.startsWith("/auth/login")) ? 5 : 50;

        if (rateLimitService.resolveBucket(ip, limit).tryConsume(1)) {
            try {
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                log.error("Error en la cadena de filtros: {}", e.getMessage());
                throw e;
            }
        } else {
            log.warn("Rate limit excedido para la IP: {} en el path: {}. Límite: {}", ip, path, limit);
            sendCustomError(request, response);
        }
    }

    private void sendCustomError(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        ErrorResponse errorDetails = ErrorResponse.builder()
                .timestamp(LocalDateTime.now().toString())
                .status(HttpStatus.SC_TOO_MANY_REQUESTS)
                .error("Too Many Requests")
                .message("Has superado el límite de peticiones. Intenta de nuevo en unos momentos.")
                .path(request.getRequestURI())
                .build();

        response.setStatus(HttpStatus.SC_TOO_MANY_REQUESTS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        try {
            response.getWriter().write(objectMapper.writeValueAsString(errorDetails));
        } catch (JsonProcessingException e) {
            log.error("Error al convertir ErrorResponse a JSON: {}", e.getMessage());
            response.getWriter().write("{\"error\": \"Too Many Requests\", \"message\": \"Límite excedido\"}");
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf == null || xf.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xf.split(",")[0];
    }
}