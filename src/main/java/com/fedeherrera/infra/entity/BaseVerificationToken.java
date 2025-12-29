package com.fedeherrera.infra.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@MappedSuperclass 
@Getter @Setter
@SuperBuilder
@NoArgsConstructor  // <--- ESTO SOLUCIONA EL ERROR "Implicit super constructor"
@AllArgsConstructor // Requerido para que SuperBuilder funcione correctamente
public abstract class BaseVerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Builder.Default // Si usas SuperBuilder, inicializa valores así
    @Column(name = "token_created_at", nullable = false)
    private LocalDateTime tokenCreatedAt = LocalDateTime.now();

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private TokenType type;

    public enum TokenType {
        VERIFICATION,
        PASSWORD_RESET
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }
}