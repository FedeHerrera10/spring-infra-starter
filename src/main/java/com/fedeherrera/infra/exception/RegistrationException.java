package com.fedeherrera.infra.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public class RegistrationException extends BaseException {

    public RegistrationException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }

    public RegistrationException(String message, HttpStatus status) {
        super(message, status);
    }
}


 