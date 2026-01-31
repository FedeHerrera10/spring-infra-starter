package com.fedeherrera.infra.service;

import com.fedeherrera.infra.entity.AuthUser;
import com.fedeherrera.infra.entity.RefreshToken;
import com.fedeherrera.infra.exception.AuthException;
import com.fedeherrera.infra.repository.RefreshTokenRepository;
import com.fedeherrera.infra.service.token.RefreshTokenService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.assertj.core.api.Assertions.within;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService Tests")
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository repo;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    @Captor
    private ArgumentCaptor<RefreshToken> tokenCaptor;

    @Captor
    private ArgumentCaptor<List<RefreshToken>> tokenListCaptor;

    private static final Long USER_ID = 1L;
    private static final String TOKEN = "refresh-token-123";
    private static final String IP_ADDRESS = "192.168.1.1";
    private static final String USER_AGENT = "Mozilla/5.0";
    private static final long VALIDITY_SECONDS = 2592000L; // 30 días

    private RefreshToken existingToken;

    @BeforeEach
    void setUp() {
        // Configurar la validez del token (esto depende de cómo lo tengas en tu
        // servicio)
        ReflectionTestUtils.setField(refreshTokenService, "validitySeconds", VALIDITY_SECONDS);

        // Setup existing token
        existingToken = new RefreshToken();
        existingToken.setId(1L);
        existingToken.setToken("old-token-456");
        existingToken.setUserId(USER_ID);
        existingToken.setExpiresAt(Instant.now().plusSeconds(VALIDITY_SECONDS));
        existingToken.setIpAddress("192.168.1.100");
        existingToken.setUserAgent("Old User Agent");
        existingToken.setRevoked(false);

    }

    // ==================== TESTS DE CREATE REFRESH TOKEN ====================

    @Test
    @DisplayName("Should create refresh token successfully")
    void testCreateRefreshToken_Success() {
        // Given
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.setId(1L);
            return token;
        });

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, USER_AGENT);

        // Then
        verify(repo).revokeAllByUserId(USER_ID);
        verify(repo, times(2)).save(tokenCaptor.capture());

        List<RefreshToken> savedTokens = tokenCaptor.getAllValues();

        // Verificar el primer save
        RefreshToken firstSave = savedTokens.get(0);
        assertEquals(TOKEN, firstSave.getToken());
        assertEquals(USER_ID, firstSave.getUserId());
        assertEquals(IP_ADDRESS, firstSave.getIpAddress());
        assertEquals(USER_AGENT, firstSave.getUserAgent());
        assertNotNull(firstSave.getExpiresAt());

        // Verificar el segundo save
        RefreshToken secondSave = savedTokens.get(1);
        assertFalse(secondSave.isRevoked());
        assertNull(secondSave.getReplacedBy());
    }

    @Test
    @DisplayName("Should revoke all previous tokens before creating new one")
    void testCreateRefreshToken_RevokePreviousTokens() {
        // Given
        when(repo.save(any(RefreshToken.class))).thenReturn(new RefreshToken());

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, USER_AGENT);

        // Then
        verify(repo).revokeAllByUserId(USER_ID);
    }

    @Test
    @DisplayName("Should set correct expiration time")
    void testCreateRefreshToken_ExpirationTime() {
        // Given
        Instant beforeCreation = Instant.now();
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS,
                USER_AGENT);

        // // Then
        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        Instant expectedExpiration = beforeCreation.plusSeconds(VALIDITY_SECONDS);

        // // Verificar que la expiración esté cerca del tiempo esperado (con margen de
        // 5
        // // segundos)

        assertThat(savedToken.getExpiresAt())
                .isCloseTo(expectedExpiration, within(30, SECONDS));

    }

    @Test
    @DisplayName("Should save IP address and user agent correctly")
    void TestSaveIPAdrresAndAgentCorrectly() {

        // Given
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, USER_AGENT);

        // Then
        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        assertEquals(IP_ADDRESS, savedToken.getIpAddress());
        assertEquals(USER_AGENT, savedToken.getUserAgent());

    }

    @Test
    @DisplayName("Should handle null IP and user agent gracefully")
    void TestHandleNullIPAndUserAgentGracefully() {
        // Given
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, null, null);

        // Then
        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        assertNull(savedToken.getIpAddress());
        assertNull(savedToken.getUserAgent());
    }

    @Test
    @DisplayName("Should set revoked to false")
    void TestSetRevokedToFalse() {
        // Given
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, USER_AGENT);

        // Then
        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        assertFalse(savedToken.isRevoked());
    }

    @Test
    @DisplayName("Should set replacedBy to null")
    void TestSetReplacedByToNull() {
        // Given
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When
        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, USER_AGENT);

        // Then
        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        assertNull(savedToken.getReplacedBy());
    }

    @Test
    @DisplayName("Should rotate token successfully")
    void TestRotateTokenSuccessfully() {

        when(repo.findByToken(anyString())).thenReturn(Optional.of(existingToken));
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        refreshTokenService.rotate(existingToken.getToken(), TOKEN, new User(USER_ID, null), IP_ADDRESS,
                USER_AGENT);

        verify(repo).findByToken(existingToken.getToken());
        // 1. Verificamos que se llamó exactamente 2 veces
        verify(repo, times(2)).save(tokenCaptor.capture());

        // 2. Obtenemos todos los tokens capturados
        List<RefreshToken> capturedTokens = tokenCaptor.getAllValues();

        // Según tu código: el primero [0] es el nuevo, el segundo [1] es el viejo
        RefreshToken newTokenCaptured = capturedTokens.get(0);
        RefreshToken oldTokenCaptured = capturedTokens.get(1);

        // 3. Verificaciones específicas
        assertNull(newTokenCaptured.getReplacedBy()); // El nuevo no reemplaza a nadie aún
        assertNotNull(oldTokenCaptured.getReplacedBy()); // El viejo sí apunta al nuevo
        assertEquals(TOKEN, oldTokenCaptured.getReplacedBy());
    }

    @Test
    @DisplayName("Should rotate token successfully")
    void TestRotateTokenNotFound() {

        when(repo.findByToken(anyString())).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class,
                () -> refreshTokenService.rotate(existingToken.getToken(), TOKEN, new User(USER_ID, null), IP_ADDRESS,
                        USER_AGENT));

        verify(repo).findByToken(existingToken.getToken());
        verify(repo, never()).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Should rotate token successfully")
    void TestRotateTokenRevoked() {
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(repo.revokeAllByUserId(USER_ID)).thenReturn(1);

        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, IP_ADDRESS);

        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        savedToken.setRevoked(true);
        assertThrows(RuntimeException.class,
                () -> refreshTokenService.rotate(savedToken.getToken(), TOKEN, new User(USER_ID, null), IP_ADDRESS,
                        USER_AGENT));

    }

    @Test
    @DisplayName("Should rotate token successfully")
    void TestRotateTokenPasswordChanged() {
        when(repo.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(repo.revokeAllByUserId(USER_ID)).thenReturn(1);

        refreshTokenService.createRefreshToken(USER_ID, TOKEN, IP_ADDRESS, IP_ADDRESS);

        verify(repo, atLeast(1)).save(tokenCaptor.capture());
        RefreshToken savedToken = tokenCaptor.getAllValues().get(0);

        assertThrows(RuntimeException.class,
                () -> refreshTokenService.rotate(savedToken.getToken(), TOKEN, new User(USER_ID, Instant.now()),
                        IP_ADDRESS,
                        USER_AGENT));

    }

    class User implements AuthUser {

        private Long id;
        private Instant passwordChangedAt;

        User() {
            this.id = 1L;
            this.passwordChangedAt = Instant.now();
        }

        User(Long id, Instant passwordChangedAt) {
            this.id = id;
            this.passwordChangedAt = passwordChangedAt;
        }

        @Override
        public Long getId() {
            return id;
        }

        @Override
        public Instant getPasswordChangedAt() {
            return passwordChangedAt;
        }

    }
}