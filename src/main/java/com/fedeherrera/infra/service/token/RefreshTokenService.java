package com.fedeherrera.infra.service.token;

import com.fedeherrera.infra.entity.AuthUser;
import com.fedeherrera.infra.entity.RefreshToken;
import com.fedeherrera.infra.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    private final RefreshTokenRepository repo;
    private final long validitySeconds = 2592000; // 30 días

    @Transactional
    public void createRefreshToken(Long userId, String token, String ip, String ua) {

        // revocar todos los tokens anteriores para este usuario
        repo.revokeAllByUserId(userId);

        // Crear la entidad del token
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(token); // Usar el token recibido
        newToken.setUserId(userId);
        newToken.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        newToken.setIpAddress(ip);
        newToken.setUserAgent(ua);
        repo.save(newToken);

        // 4. Invalidar el viejo y dejar rastro
        newToken.setRevoked(false);
        newToken.setReplacedBy(null);
        repo.save(newToken);
    }

    @Transactional(noRollbackFor = RuntimeException.class)
    public RefreshToken rotate(String oldTokenValue, String newTokenJWT, AuthUser user, String ip, String ua) {
        RefreshToken oldToken = repo.findByToken(oldTokenValue)
                .orElseThrow(() -> new RuntimeException("Token no encontrado"));

        // 1. Detección de anomalías (Token ya usado/revocado)
        if (oldToken.isRevoked()) {
            int updated = repo.revokeAllByUserId(user.getId());
            log.info("Se revocaron {} tokens del usuario {}", updated, user.getId());
            throw new RuntimeException("¡Intento de reutilización detectado! Todas las sesiones cerradas.");
        }

        // 2. Validación de seguridad (Password Changed)
        if (user.getPasswordChangedAt() != null && user.getPasswordChangedAt().isAfter(oldToken.getCreatedAt())) {
            oldToken.setRevoked(true);
            repo.save(oldToken);
            throw new RuntimeException("Sesión expirada por cambio de contraseña.");
        }

        // 3. Crear el nuevo token
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(newTokenJWT); // O tu TokenUtils
        newToken.setUserId(user.getId());
        newToken.setExpiresAt(Instant.now().plusSeconds(validitySeconds));
        newToken.setIpAddress(ip);
        newToken.setUserAgent(ua);
        repo.save(newToken);

        // 4. Invalidar el viejo y dejar rastro
        oldToken.setRevoked(true);
        oldToken.setReplacedBy(newToken.getToken());
        repo.save(oldToken);

        return newToken;
    }
}