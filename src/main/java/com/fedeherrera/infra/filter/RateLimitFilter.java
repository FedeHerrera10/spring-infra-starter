package com.fedeherrera.infra.filter;

import java.io.IOException;
import java.time.Duration; // Import faltante
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1) // Un nivel después del ForwardedHeaderFilter
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    public RateLimitFilter(@Autowired(required = false) ObjectMapper objectMapper) {
        if (objectMapper != null) {
            this.objectMapper = objectMapper;
            log.info("RateLimitFilter: Usando ObjectMapper inyectado.");
        } else {
            this.objectMapper = new ObjectMapper();
            this.objectMapper.registerModule(new JavaTimeModule());
            log.warn("RateLimitFilter: ObjectMapper manual creado.");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        // El ForwardedHeaderFilter ya procesó la IP si se configuró el Bean en
        // WebConfig
        String ip = request.getRemoteAddr();
        String key = path + "-" + ip;

        Bucket bucket = buckets.computeIfAbsent(key, k -> createNewBucket(path));

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            // Log de advertencia para detectar huella de ataque (recomendación Qodo AI)
            log.warn("Rate limit excedido - IP: {} - Path: {}", ip, path);
            sendCustomError(request, response);
        }
    }

    private Bucket createNewBucket(String path) {
        Bandwidth limit;

        if (path.startsWith("/auth/login") || path.startsWith("/auth/register")) {
            // 5 tokens cada 1 minuto
            limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        } else if (path.startsWith("/auth/refresh-token")) {
            // 20 tokens cada 1 minuto
            limit = Bandwidth.classic(20, Refill.greedy(20, Duration.ofMinutes(1)));
        } else {
            // 100 tokens cada 1 minuto
            limit = Bandwidth.classic(100, Refill.greedy(100, Duration.ofMinutes(1)));
        }

        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    private void sendCustomError(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ErrorResponse errorDetails = ErrorResponse.builder()
                .timestamp(LocalDateTime.now().toString())
                .status(HttpStatus.SC_TOO_MANY_REQUESTS)
                .error("Too Many Requests")
                .message("Has superado el límite de peticiones. Intenta de nuevo en unos momentos.")
                .path(request.getRequestURI())
                .build();

        response.setStatus(HttpStatus.SC_TOO_MANY_REQUESTS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8"); // Asegura que los acentos se vean bien

        try {
            String jsonResponse = objectMapper.writeValueAsString(errorDetails);
            response.getWriter().write(jsonResponse);
        } catch (JsonProcessingException e) {
            log.error("Error al serializar ErrorResponse: {}", e.getMessage());
            response.getWriter().write("{\"error\": \"Too Many Requests\", \"message\": \"Límite excedido\"}");
        }
    }
}