package com.fedeherrera.infra.dto;

import java.util.Map;

public record EmailEvent(
    String recipient,
    EmailTemplate template,
    Map<String, Object> properties // Datos dinámicos para la plantilla
) {}