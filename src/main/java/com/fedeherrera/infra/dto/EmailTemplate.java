package com.fedeherrera.infra.dto;

public enum EmailTemplate {
    USER_VERIFICATION("Verifica tu cuenta"),
    PASSWORD_RESET("Recupera tu contraseña"),
    WELCOME_MESSAGE("¡Bienvenido a nuestra plataforma!");

    private final String subject;

    EmailTemplate(String subject) {
        this.subject = subject;
    }

    public String getSubject() { return subject; }
}