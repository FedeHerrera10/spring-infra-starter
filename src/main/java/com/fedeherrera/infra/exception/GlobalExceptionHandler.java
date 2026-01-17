package com.fedeherrera.infra.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.fedeherrera.infra.dto.ErrorResponse;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

        ErrorResponse response = ErrorResponse.builder()
                .timestamp(LocalDateTime.now().toString())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Error")
                .message("Los datos enviados no son válidos")
                .path(request.getServletPath())
                .validationErrors(errors)
                .build();

        log.error("Error de validación en [{}]: {}", request.getServletPath(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler({ RegistrationException.class, AuthException.class })
    public ResponseEntity<ErrorResponse> handleBusinessExceptions(RuntimeException ex, HttpServletRequest request) {
        return buildErrorResponse(
                ex,
                HttpStatus.BAD_REQUEST,
                "Business Logic Error",
                "Error de negocio",
                request);
    }

    @ExceptionHandler(NotFoundEntityException.class)
    public ResponseEntity<ErrorResponse> handleNotFoundException(NotFoundEntityException ex,
            HttpServletRequest request) {
        return buildErrorResponse(
                ex,
                HttpStatus.NOT_FOUND,
                "Not Found",
                "El recurso solicitado no fue encontrado",
                request);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> handleRuntimeException(RuntimeException ex, HttpServletRequest request) {
        return buildErrorResponse(
                ex,
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Runtime Error",
                "Ocurrió un error en tiempo de ejecución",
                request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAllExceptions(Exception ex, HttpServletRequest request) {
        return buildErrorResponse(
                ex,
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "Ocurrió un error inesperado en el servidor",
                request);
    }

    @ExceptionHandler({ ExpiredJwtException.class, MalformedJwtException.class, SignatureException.class,
            JwtAuthenticationException.class })
    public ResponseEntity<ErrorResponse> handleJwtAuthenticationException(Exception ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String errorType = "Authentication Error";
        String defaultMessage = "Error de autenticación";
        if (ex instanceof ExpiredJwtException) {
            defaultMessage = "El token JWT ha expirado";
        } else if (ex instanceof MalformedJwtException || ex instanceof SignatureException) {
            defaultMessage = "Token JWT inválido o mal formado";
        }
        return buildErrorResponse(
                ex,
                status,
                errorType,
                defaultMessage,
                request);
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse(
            Exception ex,
            HttpStatus status,
            String errorType,
            String defaultMessage,
            HttpServletRequest request) {
        log.error("{} en [{}]: {}", errorType, request.getServletPath(), ex.getMessage(), ex);

        String message = ex.getMessage() != null && !ex.getMessage().isBlank()
                ? ex.getMessage()
                : defaultMessage;

        return ResponseEntity.status(status).body(
                ErrorResponse.builder()
                        .timestamp(LocalDateTime.now().toString())
                        .status(status.value())
                        .error(errorType)
                        .message(message)
                        .path(request.getServletPath())
                        .build());
    }
}