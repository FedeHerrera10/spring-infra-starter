package com.fedeherrera.infra.config;

import com.fedeherrera.infra.service.email.DefaultEmailServiceImpl;
import com.fedeherrera.infra.service.email.EmailEventListener;
import com.fedeherrera.infra.service.email.EmailService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
public class EmailAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(EmailService.class)
    public EmailService emailService(JavaMailSender mailSender) {
        return new DefaultEmailServiceImpl(mailSender);
    }

    @Bean
    @ConditionalOnMissingBean(EmailEventListener.class) // <--- ESTO FALTA
    public EmailEventListener emailEventListener(EmailService emailService) {
        System.out.println("✅ EmailEventListener ha sido cargado por el Starter");
        return new EmailEventListener(emailService);
    }
}