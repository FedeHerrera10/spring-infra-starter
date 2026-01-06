package com.fedeherrera.infra.service.user;

import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.repository.BaseUserRepository;
import com.fedeherrera.infra.service.verfication.VerificationService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;


@Slf4j
@RequiredArgsConstructor
public abstract class UserServiceImpl<T extends BaseUser, V extends BaseVerificationToken> implements UserService<T> {

    private final BaseUserRepository<T> userRepository;
    // CAMBIO CLAVE: Usamos el genérico V para que coincida con el Bean de la App Demo
    private final VerificationService<T, V> verificationService;
    private final PasswordEncoder passwordEncoder;
    
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_TIME_MINUTES = 15;

    @Override
    public T save(T user) {
        return userRepository.save(user);
    }

    @Override
    public Optional<T> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public Optional<T> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<T> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        T user = verificationService.validatePasswordResetToken(token)
                .orElseThrow(() -> new RegistrationException("Token inválido o expirado"));

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(Instant.now());
        
        userRepository.save(user);
        verificationService.deleteToken(token);
        
        log.info("Contraseña actualizada para: {}. Token invalidado.", user.getEmail());
    }

    @Override
    @Transactional
    public void registerFailedAttempt(String username) {
        userRepository.findByUsername(username).ifPresent(user -> {
            if (user.isAccountNonLocked()) {
                user.setFailedAttempts(user.getFailedAttempts() + 1);
                
                if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                    user.setAccountNonLocked(false);
                    user.setLockTime(LocalDateTime.now());
                    log.warn("CUENTA BLOQUEADA: {}", username);
                }
                userRepository.save(user);
            }
        });
    }

    @Override
    @Transactional
    public void resetFailedAttempts(Long id) {
        userRepository.findById(id).ifPresent(user -> {
            user.setFailedAttempts(0);
            userRepository.save(user);
        });
    }

    @Override
    @Transactional
    public void unlockExpiredAccounts() {
        LocalDateTime expirationThreshold = LocalDateTime.now().minusMinutes(LOCK_TIME_MINUTES);
        List<T> lockedUsers = userRepository.findAllByAccountNonLockedFalseAndLockTimeBefore(expirationThreshold);

        if (!lockedUsers.isEmpty()) {
            lockedUsers.forEach(user -> {
                user.setAccountNonLocked(true);
                user.setFailedAttempts(0);
                user.setLockTime(null);
                log.info("CUENTA DESBLOQUEADA: {}", user.getUsername());
            });
            userRepository.saveAll(lockedUsers);
        }
    }
    
    // Método abstracto para evitar Reflection. La App Demo dirá 'return new User()'
    @Override
    public abstract T createNewInstance();
}