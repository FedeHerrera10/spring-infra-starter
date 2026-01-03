package com.fedeherrera.infra.repository;

import com.fedeherrera.infra.entity.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@NoRepositoryBean // Esta es la clave
public interface BaseUserRepository<T extends BaseUser> extends JpaRepository<T, Long> {
    Optional<T> findByUsername(String username);

    Optional<T> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedAttempts = u.failedAttempts + 1 WHERE u.username = :username")
    void incrementFailedAttempts(String username);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.accountNonLocked = false, u.lockTime = :lockTime WHERE u.username = :username")
    void lockUser(String username, LocalDateTime lockTime);

    List<T> findAllByAccountNonLockedFalseAndLockTimeBefore(LocalDateTime time);

    
}