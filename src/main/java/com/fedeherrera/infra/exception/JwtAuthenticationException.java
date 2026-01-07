package com.fedeherrera.infra.exception;



public class JwtAuthenticationException extends AuthException {
    public JwtAuthenticationException(String message) {
        super(message);
    }

    public JwtAuthenticationException(String message, Throwable cause) {
        super(message);
    }
}