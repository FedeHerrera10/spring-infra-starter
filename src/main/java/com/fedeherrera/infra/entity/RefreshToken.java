package com.fedeherrera.infra.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_token", columnList = "token"),
        @Index(name = "idx_user_id", columnList = "userId")
})
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    @Column(nullable = false)
    private Long userId; // Referencia numérica, no de objeto

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    private boolean revoked = false;

    private String replacedBy; // Para rastrear la cadena de rotación

    private String ipAddress;
    private String userAgent;

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiresAt);
    }
}
