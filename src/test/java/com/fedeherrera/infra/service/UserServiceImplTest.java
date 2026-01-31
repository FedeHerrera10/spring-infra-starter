package com.fedeherrera.infra.service;

import com.fasterxml.jackson.databind.JsonSerializable.Base;
import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.repository.BaseUserRepository;
import com.fedeherrera.infra.service.user.UserServiceImpl;
import com.fedeherrera.infra.service.verfication.VerificationService;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private BaseUserRepository<TestUser> userRepository;
    @Mock
    private VerificationService<TestUser, TestVerificationToken> verificationService;
    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImplTestable userService; // Usamos nuestra clase "concreta"

    private TestUser tUser;

    public static class UserServiceImplTestable extends UserServiceImpl<TestUser, TestVerificationToken> {
        public UserServiceImplTestable(BaseUserRepository<TestUser> repo,
                VerificationService<TestUser, TestVerificationToken> vService,
                PasswordEncoder encoder) {
            super(repo, vService, encoder);
        }

        @Override
        public TestUser createNewInstance() {
            return new TestUser();
        }
    }

    @BeforeEach
    void setUp() {
        tUser = new TestUser();
        tUser.setId(1L);
        tUser.setUsername("testuser");
        tUser.setEmail("test@example.com");
        tUser.setPassword("password");
        tUser.setAccountNonLocked(true);
        tUser.setFailedAttempts(0);
    }

    @Test
    void userSaved() {
        when(userRepository.save(any(TestUser.class))).thenReturn(tUser);

        TestUser savedUser = userService.save(tUser);

        assertNotNull(savedUser);
        assertEquals(tUser.getId(), savedUser.getId());
        assertEquals(tUser.getUsername(), savedUser.getUsername());
        assertEquals(tUser.getEmail(), savedUser.getEmail());
        assertEquals(tUser.getPassword(), savedUser.getPassword());
        assertEquals(tUser.isAccountNonLocked(), savedUser.isAccountNonLocked());
        assertEquals(tUser.getFailedAttempts(), savedUser.getFailedAttempts());
    }

    @Test
    void userFindById() {
        when(userRepository.findById(any(Long.class))).thenReturn(Optional.of(tUser));

        Optional<TestUser> foundUser = userService.findById(1L);

        assertTrue(foundUser.isPresent());
        assertEquals(tUser.getId(), foundUser.get().getId());
        assertEquals(tUser.getUsername(), foundUser.get().getUsername());
        assertEquals(tUser.getEmail(), foundUser.get().getEmail());
        assertEquals(tUser.getPassword(), foundUser.get().getPassword());
        assertEquals(tUser.isAccountNonLocked(), foundUser.get().isAccountNonLocked());
        assertEquals(tUser.getFailedAttempts(), foundUser.get().getFailedAttempts());
    }

    @Test
    void userFindByIdNotFound() {
        when(userRepository.findById(any(Long.class))).thenReturn(Optional.empty());

        Optional<TestUser> foundUser = userService.findById(1L);

        assertFalse(foundUser.isPresent());
    }

    @Test
    void userFindByUsername() {
        when(userRepository.findByUsername(any(String.class))).thenReturn(Optional.of(tUser));

        Optional<TestUser> foundUser = userService.findByUsername("testuser");

        assertTrue(foundUser.isPresent());
        assertEquals(tUser.getId(), foundUser.get().getId());
        assertEquals(tUser.getUsername(), foundUser.get().getUsername());
        assertEquals(tUser.getEmail(), foundUser.get().getEmail());
        assertEquals(tUser.getPassword(), foundUser.get().getPassword());
        assertEquals(tUser.isAccountNonLocked(), foundUser.get().isAccountNonLocked());
        assertEquals(tUser.getFailedAttempts(), foundUser.get().getFailedAttempts());
    }

    @Test
    void userFindByUsernameNotFound() {
        when(userRepository.findByUsername(any(String.class))).thenReturn(Optional.empty());

        Optional<TestUser> foundUser = userService.findByUsername("testuser");

        assertFalse(foundUser.isPresent());
    }

    @Test
    void userFindByEmail() {
        when(userRepository.findByEmail(any(String.class))).thenReturn(Optional.of(tUser));

        Optional<TestUser> foundUser = userService.findByEmail("test@example.com");

        assertTrue(foundUser.isPresent());
        assertEquals(tUser.getId(), foundUser.get().getId());
        assertEquals(tUser.getUsername(), foundUser.get().getUsername());
        assertEquals(tUser.getEmail(), foundUser.get().getEmail());
        assertEquals(tUser.getPassword(), foundUser.get().getPassword());
        assertEquals(tUser.isAccountNonLocked(), foundUser.get().isAccountNonLocked());
        assertEquals(tUser.getFailedAttempts(), foundUser.get().getFailedAttempts());
    }

    @Test
    void userFindByEmailNotFound() {
        when(userRepository.findByEmail(any(String.class))).thenReturn(Optional.empty());

        Optional<TestUser> foundUser = userService.findByEmail("test@example.com");

        assertFalse(foundUser.isPresent());
    }

    @Test
    void userExistsByUsername() {
        when(userRepository.existsByUsername(any(String.class))).thenReturn(true);

        boolean exists = userService.existsByUsername("testuser");

        assertTrue(exists);
    }

    @Test
    void userExistsByUsernameNotFound() {
        when(userRepository.existsByUsername(any(String.class))).thenReturn(false);

        boolean exists = userService.existsByUsername("testuser");

        assertFalse(exists);
    }

    @Test
    void userExistsByEmail() {
        when(userRepository.existsByEmail(any(String.class))).thenReturn(true);

        boolean exists = userService.existsByEmail("test@example.com");

        assertTrue(exists);
    }

    @Test
    void userExistsByEmailNotFound() {
        when(userRepository.existsByEmail(any(String.class))).thenReturn(false);

        boolean exists = userService.existsByEmail("test@example.com");

        assertFalse(exists);
    }

    @Test
    void userResetPassword() {
        when(verificationService.validatePasswordResetToken(any(String.class))).thenReturn(Optional.of(tUser));
        when(passwordEncoder.encode(any(String.class))).thenReturn("encodedPassword");
        when(userRepository.save(any(TestUser.class))).thenReturn(tUser);

        userService.resetPassword("token", "newPassword");

        verify(verificationService, times(1)).validatePasswordResetToken(any(String.class));
        verify(passwordEncoder, times(1)).encode(any(String.class));
        verify(userRepository, times(1)).save(any(TestUser.class));
        verify(verificationService, times(1)).deleteToken(any(String.class));
    }

    @Test
    void userResetPasswordTokenNotFound() {
        when(verificationService.validatePasswordResetToken(any(String.class)))
                .thenThrow(new RegistrationException("Token inválido o expirado"));

        assertThrows(RegistrationException.class, () -> {
            userService.resetPassword("token", "newPassword");
        });

        verify(verificationService, times(1)).validatePasswordResetToken(any(String.class));
        verify(passwordEncoder, times(0)).encode(any(String.class));
        verify(userRepository, times(0)).save(any(TestUser.class));
        verify(verificationService, times(0)).deleteToken(any(String.class));
    }

    @Test
    void userRegisterFailedAttempt() {
        when(userRepository.findByUsername(any(String.class))).thenReturn(Optional.of(tUser));
        when(userRepository.save(any(TestUser.class))).thenReturn(tUser);

        userService.registerFailedAttempt("testuser");

        verify(userRepository, times(1)).findByUsername(any(String.class));
        verify(userRepository, times(1)).save(any(TestUser.class));
    }

    @Test
    void userRegisterFailedAttemptNotFound() {
        when(userRepository.findByUsername(any(String.class))).thenReturn(Optional.empty());

        userService.registerFailedAttempt("testuser");

        verify(userRepository, times(1)).findByUsername(any(String.class));
        verify(userRepository, times(0)).save(any(TestUser.class));
    }

    @Test
    void userResetFailedAttempts() {
        when(userRepository.findById(any(Long.class))).thenReturn(Optional.of(tUser));
        when(userRepository.save(any(TestUser.class))).thenReturn(tUser);

        userService.resetFailedAttempts(1L);

        verify(userRepository, times(1)).findById(any(Long.class));
        verify(userRepository, times(1)).save(any(TestUser.class));
    }

    @Test
    void userResetFailedAttemptsNotFound() {
        when(userRepository.findById(any(Long.class))).thenReturn(Optional.empty());

        userService.resetFailedAttempts(1L);

        verify(userRepository, times(1)).findById(any(Long.class));
        verify(userRepository, times(0)).save(any(TestUser.class));
    }

    @Test
    void userUnlockExpiredAccounts() {
        when(userRepository.findAllByAccountNonLockedFalseAndLockTimeBefore(any(LocalDateTime.class)))
                .thenReturn(List.of(tUser));
        when(userRepository.saveAll(any(List.class))).thenReturn(List.of(tUser));

        userService.unlockExpiredAccounts();

        verify(userRepository, times(1)).findAllByAccountNonLockedFalseAndLockTimeBefore(any(LocalDateTime.class));
        verify(userRepository, times(1)).saveAll(any(List.class));
    }

    @Test
    void userUnlockExpiredAccountsEmpty() {
        when(userRepository.findAllByAccountNonLockedFalseAndLockTimeBefore(any(LocalDateTime.class)))
                .thenReturn(List.of());

        userService.unlockExpiredAccounts();

        verify(userRepository, times(1)).findAllByAccountNonLockedFalseAndLockTimeBefore(any(LocalDateTime.class));
        verify(userRepository, times(0)).saveAll(any(List.class));
    }

}

class TestUser extends BaseUser {
    // Add any specific fields or methods for testing if needed
}

class TestToken extends BaseVerificationToken {
    // Add any specific fields or methods for testing if needed
}

class TestVerificationToken extends BaseVerificationToken {
    // Add any specific fields or methods for testing if needed
}
