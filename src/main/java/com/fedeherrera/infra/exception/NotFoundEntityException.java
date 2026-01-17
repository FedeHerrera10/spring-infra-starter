package com.fedeherrera.infra.exception;

import org.springframework.http.HttpStatus;

public class NotFoundEntityException extends BaseException {
    public NotFoundEntityException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
