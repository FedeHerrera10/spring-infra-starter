package com.fedeherrera.infra.service.verfication;

import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;

import java.util.Optional;

// Usamos <T extends BaseUser> para que sea compatible con cualquier User
public interface VerificationService<T extends BaseUser, V extends BaseVerificationToken> {
    /**
     * Genera un token de verificación para un usuario genérico.
     */
    V createToken(T user);

    /**
     * Valida un token y devuelve el usuario si es válido.
     */
    Optional<T> validateToken(String token);

    /**
     * Elimina un token.
     */
    void deleteToken(String token);

    /**
     * Valida el token de reset y devuelve el usuario tipo T.
     */
    Optional<T> validatePasswordResetToken(String token);
    
    /**
     * Crea el token de reset para el usuario tipo T.
     */
    V createPasswordResetToken(T user);
}