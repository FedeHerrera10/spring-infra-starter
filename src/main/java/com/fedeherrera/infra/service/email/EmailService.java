package com.fedeherrera.infra.service.email;

import com.fedeherrera.infra.dto.EmailEvent;

public interface EmailService {
    void sendEmail(EmailEvent event);
    String buildContent(EmailEvent event);
}   