package com.fedeherrera.infra.exception;

import org.springframework.http.HttpStatus;
import lombok.Getter;

@Getter
public class AuthException extends BaseException {
    public AuthException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }

    public AuthException(String message, HttpStatus status) {
        super(message, status);
    }
}   