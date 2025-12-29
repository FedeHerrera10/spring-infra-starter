package com.fedeherrera.infra.service.user;

import com.fedeherrera.infra.entity.BaseUser;
import java.util.Optional;

public interface UserService<T extends BaseUser> {

    T save(T user);

    Optional<T> findById(Long id);

    Optional<T> findByUsername(String username);

    Optional<T> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    void registerFailedAttempt(String username);

    void resetFailedAttempts(Long id);

    void unlockExpiredAccounts();

    void resetPassword(String token, String newPassword);
    T createNewInstance();
}