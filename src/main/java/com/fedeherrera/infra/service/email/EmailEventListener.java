package com.fedeherrera.infra.service.email;

import com.fedeherrera.infra.dto.EmailEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class EmailEventListener {

    private final EmailService emailService;

    @Async
    @EventListener
    public void handleEmailEvent(EmailEvent event) {
        log.info("Procesando envío de email para: {}", event.recipient());
        emailService.sendEmail(event);
    }
}