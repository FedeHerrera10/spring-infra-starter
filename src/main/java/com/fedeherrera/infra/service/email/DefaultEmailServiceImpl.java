package com.fedeherrera.infra.service.email;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.fedeherrera.infra.dto.EmailEvent;

@Slf4j
@RequiredArgsConstructor
@Service
public class DefaultEmailServiceImpl implements EmailService {

    @Value("${spring.mail.from:admin@default.com}") // Lee 'spring.mail.from' de la App Final
    private String fromEmail;
    private final JavaMailSender mailSender;

    @Override
    // Nota: El @Async se mueve al Listener para mayor control, 
    // pero puedes dejarlo aquí si prefieres.
    public void sendEmail(EmailEvent event) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(event.recipient());
            message.setSubject(event.template().getSubject());
            
            // Aquí podrías usar Thymeleaf, por ahora usamos un generador de texto simple
            String content = buildContent(event); 
            message.setText(content);
            
            mailSender.send(message);
            log.info("📧 Correo [{}] enviado a: {}", event.template(), event.recipient());
        } catch (Exception e) {
            log.error("❌ Error enviando correo a {}: {}", event.recipient(), e.getMessage());
        }
    }

    @Override
    public String buildContent(EmailEvent event) {
        // Lógica simple para extraer datos del mapa
        // Si usas Thymeleaf, aquí llamarías al engine.
        StringBuilder body = new StringBuilder();
        event.properties().forEach((k, v) -> body.append(k).append(": ").append(v).append("\n"));
        return body.toString();
    }
}