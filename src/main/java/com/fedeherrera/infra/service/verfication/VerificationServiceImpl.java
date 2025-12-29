package com.fedeherrera.infra.service.verfication;

import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.repository.BaseVerificationTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@RequiredArgsConstructor
public abstract class VerificationServiceImpl<T extends BaseUser, V extends BaseVerificationToken> 
    implements VerificationService<T, V> {

    // Usamos el repositorio genérico que creamos antes
    protected final BaseVerificationTokenRepository<V> tokenRepository;
    
    
    
    // Este método lo implementará tu Proyecto Demo para crear el token real
    protected abstract V createTokenInstance(T user, String token, LocalDateTime expiresAt, String type);

    // Este método lo implementará tu Proyecto Demo para obtener el usuario del token
    protected abstract T getUserFromToken(V token);

    @Override
    @Transactional
    public V createToken(T user) {
        String tokenStr = UUID.randomUUID().toString();
        V token = createTokenInstance(user, tokenStr, LocalDateTime.now().plusHours(24), BaseVerificationToken.TokenType.VERIFICATION.name());
        tokenRepository.save(token);
        return token;
    }

    @Override
    @Transactional
    public V createPasswordResetToken(T user) {
        String tokenStr = UUID.randomUUID().toString();
        V token = createTokenInstance(user, tokenStr, LocalDateTime.now().plusHours(1), BaseVerificationToken.TokenType.PASSWORD_RESET.name());
        return tokenRepository.save(token);
    }

    @Override
    public Optional<T> validateToken(String token) {
        return tokenRepository.findByToken(token)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .map(this::getUserFromToken);
    }

    @Override
    public Optional<T> validatePasswordResetToken(String token) {
        return tokenRepository.findByToken(token)
                // Aquí podrías necesitar un campo 'type' en BaseVerificationToken si quieres filtrar
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .map(this::getUserFromToken);
    }

    @Override
    @Transactional
    public void deleteToken(String token) {
        tokenRepository.deleteByToken(token);
    }
}