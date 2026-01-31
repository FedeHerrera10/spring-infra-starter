package com.fedeherrera.infra.service;

import com.fedeherrera.infra.dto.*;
import com.fedeherrera.infra.entity.*;
import com.fedeherrera.infra.exception.AuthException;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.service.auth.AuthService;
import com.fedeherrera.infra.service.role.RoleService;
import com.fedeherrera.infra.service.token.RefreshTokenService;
import com.fedeherrera.infra.service.user.UserService;
import com.fedeherrera.infra.service.verfication.VerificationService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Tests")
class AuthServiceImplTest {

    @Mock
    private UserService<TestUser> userService;

    @Mock
    private RoleService roleService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private VerificationService<TestUser, TestVerificationToken> verificationService;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private GoogleTokenVerifierService googleTokenVerifierService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private AuthService<TestUser, TestVerificationToken> authService;

    private TestUser testUser;
    private Role roleUser;
    private TestVerificationToken verificationToken;

    @BeforeEach
    void setUp() {
        // Inyectar valores de configuración
        ReflectionTestUtils.setField(authService, "verifyUrl", "http://localhost:8080/api/v1/auth/verify");
        ReflectionTestUtils.setField(authService, "resetUrl", "http://localhost:8080/api/v1/auth/reset-password");

        // Setup Role
        roleUser = new Role();
        roleUser.setId(1L);
        roleUser.setName("ROLE_USER");

        // Setup User
        testUser = new TestUser();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.setPassword("encodedPassword");
        testUser.setEnabled(true);
        testUser.setAccountNonLocked(true);
        testUser.setRoles(Set.of(roleUser));

        // Setup Verification Token
        verificationToken = new TestVerificationToken();
        verificationToken.setToken("test-token-123");
        // verificationToken.setUser(testUser);
    }

    // ==================== TESTS DE REGISTRO PÚBLICO ====================

    @Test
    @DisplayName("Should register public user successfully")
    void testRegisterPublic_Success() {
        // Given
        PublicRegisterRequest request = new PublicRegisterRequest();
        request.setUsername("newuser");
        request.setEmail("newuser@example.com");
        request.setFirstName("New");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername(anyString())).thenReturn(false);
        when(userService.existsByEmail(anyString())).thenReturn(false);
        when(roleService.findByName("ROLE_USER")).thenReturn(Optional.of(roleUser));
        when(userService.createNewInstance()).thenReturn(new TestUser());
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userService.save(any(TestUser.class))).thenReturn(testUser);
        when(verificationService.createToken(any(TestUser.class))).thenReturn(verificationToken);

        // When
        authService.registerPublic(request);

        // Then
        verify(userService).existsByUsername("newuser");
        verify(userService).existsByEmail("newuser@example.com");
        verify(userService).createNewInstance();
        verify(passwordEncoder).encode("password123");
        verify(userService).save(any(TestUser.class));
        verify(verificationService).createToken(any(TestUser.class));
        verify(eventPublisher).publishEvent(any(EmailEvent.class));
    }

    @Test
    @DisplayName("Should throw exception when username already exists")
    void testRegisterPublic_UsernameExists() {
        // Given
        PublicRegisterRequest request = new PublicRegisterRequest();
        request.setUsername("existinguser");
        request.setEmail("new@example.com");
        request.setFirstName("New");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername("existinguser")).thenReturn(true);

        // When & Then
        RegistrationException exception = assertThrows(
                RegistrationException.class,
                () -> authService.registerPublic(request));

        assertEquals("Username ya registrado.", exception.getMessage());
        verify(userService).existsByUsername("existinguser");
        verify(userService, never()).save(any());
    }

    @Test
    @DisplayName("Should throw exception when email already exists")
    void testRegisterPublic_EmailExists() {
        // Given
        PublicRegisterRequest request = new PublicRegisterRequest();
        request.setUsername("newuser");
        request.setEmail("existing@example.com");
        request.setFirstName("New");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername("newuser")).thenReturn(false);
        when(userService.existsByEmail("existing@example.com")).thenReturn(true);

        // When & Then
        RegistrationException exception = assertThrows(
                RegistrationException.class,
                () -> authService.registerPublic(request));

        assertEquals("Email ya registrado.", exception.getMessage());
        verify(userService).existsByEmail("existing@example.com");
        verify(userService, never()).save(any());
    }

    @Test
    @DisplayName("Should throw exception when ROLE_USER not found")
    void testRegisterPublic_RoleNotFound() {
        // Given
        PublicRegisterRequest request = new PublicRegisterRequest();
        request.setUsername("newuser");
        request.setEmail("new@example.com");
        request.setFirstName("New");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername(anyString())).thenReturn(false);
        when(userService.existsByEmail(anyString())).thenReturn(false);
        when(roleService.findByName("ROLE_USER")).thenReturn(Optional.empty());

        // When & Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authService.registerPublic(request));

        assertEquals("ROLE_USER not found", exception.getMessage());
    }

    // ==================== TESTS DE LOGIN ====================

    @Test
    @DisplayName("Should login successfully with valid credentials")
    void testLogin_Success() {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123");

        UserPrincipal principal = new UserPrincipal(testUser);
        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(principal);
        when(jwtService.generateToken(principal)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(principal)).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.login(request);

        // Then
        assertNotNull(response);
        assertEquals("testuser", response.getUsername());
        assertEquals("access-token", response.getAccessToken());
        assertEquals("refresh-token", response.getRefreshToken());
        assertEquals("ROLE_USER", response.getRole());

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService).generateToken(principal);
        verify(jwtService).generateRefreshToken(principal);
    }

    @Test
    @DisplayName("Should register failed attempt on bad credentials")
    void testLogin_BadCredentials() {
        // Given
        LoginRequest request = new LoginRequest("testuser", "wrongpassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.login(request));

        assertEquals("Credenciales inválidas", exception.getMessage());
        verify(userService).registerFailedAttempt("testuser");
    }

    @Test
    @DisplayName("Should throw exception when account is locked")
    void testLogin_AccountLocked() {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new LockedException("Account locked"));

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.login(request));

        assertEquals("Cuenta bloqueada por seguridad.", exception.getMessage());
        verify(userService, never()).registerFailedAttempt(anyString());
    }

    @Test
    @DisplayName("Should throw exception when account is disabled")
    void testLogin_AccountDisabled() {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new DisabledException("Account disabled"));

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.login(request));

        assertEquals("Usuario no verificado", exception.getMessage());
    }

    @Test
    @DisplayName("Should reset failed attempts after successful login")
    void testLogin_ResetFailedAttempts() {
        // Given
        LoginRequest request = new LoginRequest("testuser", "password123");
        testUser.setFailedAttempts(3);

        UserPrincipal principal = new UserPrincipal(testUser);
        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(principal);
        when(jwtService.generateToken(principal)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(principal)).thenReturn("refresh-token");

        // When
        authService.login(request);

        // Then
        verify(userService).resetFailedAttempts(testUser.getId());
    }

    // ==================== TESTS DE GOOGLE LOGIN ====================

    @Test
    @DisplayName("Should login with Google for existing user")
    void testLoginWithGoogle_ExistingUser() throws Exception {
        // Given
        String googleToken = "google-token-123";
        GoogleIdToken.Payload payload = mock(GoogleIdToken.Payload.class);

        when(googleTokenVerifierService.verify(googleToken)).thenReturn(payload);
        when(payload.getEmail()).thenReturn("test@example.com");
        when(payload.get("name")).thenReturn("Test User");
        when(userService.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(any(UserPrincipal.class))).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any(UserPrincipal.class))).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.loginWithGoogle(googleToken);

        // Then
        assertNotNull(response);
        assertEquals("testuser", response.getUsername());
        verify(googleTokenVerifierService).verify(googleToken);
        verify(userService).findByEmail("test@example.com");
        verify(userService, never()).save(any()); // No se crea usuario nuevo
    }

    @Test
    @DisplayName("Should create new user when logging with Google for first time")
    void testLoginWithGoogle_NewUser() throws Exception {
        // Given
        String googleToken = "google-token-123";
        GoogleIdToken.Payload payload = mock(GoogleIdToken.Payload.class);

        when(googleTokenVerifierService.verify(googleToken)).thenReturn(payload);
        when(payload.getEmail()).thenReturn("newgoogle@example.com");
        when(payload.get("name")).thenReturn("New Google User");
        when(userService.findByEmail("newgoogle@example.com")).thenReturn(Optional.empty());
        when(userService.createNewInstance()).thenReturn(new TestUser());
        when(roleService.findByName("ROLE_USER")).thenReturn(Optional.of(roleUser));
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-random-password");
        when(userService.save(any(TestUser.class))).thenReturn(testUser);
        when(jwtService.generateToken(any(UserPrincipal.class))).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any(UserPrincipal.class))).thenReturn("refresh-token");

        // When
        LoginResponse response = authService.loginWithGoogle(googleToken);

        // Then
        assertNotNull(response);
        verify(userService).createNewInstance();
        verify(userService).save(any(TestUser.class));
        verify(passwordEncoder).encode(anyString());
    }

    @Test
    @DisplayName("Should throw exception when Google token is invalid")
    void testLoginWithGoogle_InvalidToken() throws Exception {
        // Given
        String googleToken = "invalid-token";
        when(googleTokenVerifierService.verify(googleToken)).thenThrow(new AuthException("Token de Google inválido"));

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.loginWithGoogle(googleToken));

        assertEquals("Error durante la autenticación con Google", exception.getMessage());
    }

    @DisplayName("Should throw exception when Google user is disabled")
    void testLoginWithGoogle_DisabledUser() throws Exception {
        // Given
        String googleToken = "google-token-123";
        GoogleIdToken.Payload payload = mock(GoogleIdToken.Payload.class);
        testUser.setEnabled(false);

        when(googleTokenVerifierService.verify(googleToken)).thenReturn(payload);
        when(payload.getEmail()).thenReturn("test@example.com");
        when(payload.get("name")).thenReturn("Test User");
        when(userService.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.loginWithGoogle(googleToken));

        assertEquals("El usuario está deshabilitado", exception.getMessage());
    }

    // ==================== TESTS DE RESET PASSWORD ====================

    @Test
    @DisplayName("Should initiate password reset successfully")
    void testResetPassword_Success() {
        // Given
        when(verificationService.createPasswordResetToken(testUser)).thenReturn(verificationToken);
        when(userService.save(any(TestUser.class))).thenReturn(testUser);

        // When
        authService.resetPassword(testUser);

        // Then
        assertFalse(testUser.isEnabled()); // Usuario debe quedar deshabilitado
        verify(verificationService).createPasswordResetToken(testUser);
        verify(userService).save(testUser);
        verify(eventPublisher).publishEvent(any(EmailEvent.class));
    }

    // ==================== TESTS DE REFRESH TOKEN ====================

    @DisplayName("Should refresh token successfully")
    void testRefreshToken_Success() {
        // Given
        String oldRefreshToken = "old-refresh-token";
        String ip = "127.0.0.1";
        String userAgent = "Mozilla/5.0";

        RefreshToken newRefreshTokenEntity = new RefreshToken();
        newRefreshTokenEntity.setToken("new-refresh-token");

        when(jwtService.extractUsername(oldRefreshToken)).thenReturn("testuser");
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken(any(UserPrincipal.class))).thenReturn("new-access-token");
        when(jwtService.generateRefreshToken(any(UserPrincipal.class))).thenReturn("new-refresh-token");
        when(refreshTokenService.rotate(anyString(), anyString(), any(AuthUser.class), anyString(), anyString()))
                .thenReturn(newRefreshTokenEntity);

        // When
        LoginResponse response = authService.refreshToken(oldRefreshToken, ip, userAgent);

        // Then
        assertNotNull(response);
        assertEquals("testuser", response.getUsername());
        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());

        verify(refreshTokenService).rotate(eq(oldRefreshToken), eq("new-refresh-token"),
                any(AuthUser.class), eq(ip), eq(userAgent));
    }

    @Test
    @DisplayName("Should throw exception when user not found during refresh")
    void testRefreshToken_UserNotFound() {
        // Given
        String oldRefreshToken = "old-refresh-token";

        when(jwtService.extractUsername(oldRefreshToken)).thenReturn("nonexistent");
        when(userService.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        AuthException exception = assertThrows(
                AuthException.class,
                () -> authService.refreshToken(oldRefreshToken, "127.0.0.1", "Mozilla"));

        assertEquals("Usuario no encontrado", exception.getMessage());
    }

    // ==================== TESTS DE REGISTRO INTERNO ====================

    @Test
    @DisplayName("Should register internal user successfully")
    void testRegisterInternal_Success() {
        // Given
        AdminCreateUserRequest request = new AdminCreateUserRequest();
        request.setUsername("adminuser");
        request.setEmail("admin@example.com");
        request.setFirstName("Admin");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername("adminuser")).thenReturn(false);
        when(userService.existsByEmail("admin@example.com")).thenReturn(false);
        when(roleService.findByName("ROLE_USER")).thenReturn(Optional.of(roleUser));
        when(userService.createNewInstance()).thenReturn(new TestUser());
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(userService.save(any(TestUser.class))).thenReturn(testUser);

        // When
        authService.registerInternal(request);

        // Then
        verify(userService).existsByUsername("adminuser");
        verify(userService).existsByEmail("admin@example.com");
        verify(userService).createNewInstance();
        verify(userService).save(any(TestUser.class));
    }

    @Test
    @DisplayName("Should throw exception when internal registration username exists")
    void testRegisterInternal_UsernameExists() {
        // Given
        AdminCreateUserRequest request = new AdminCreateUserRequest();
        request.setUsername("existinguser");
        request.setEmail("new@example.com");
        request.setFirstName("Admin");
        request.setLastName("User");
        request.setPassword("password123");

        when(userService.existsByUsername("existinguser")).thenReturn(true);

        // When & Then
        RegistrationException exception = assertThrows(
                RegistrationException.class,
                () -> authService.registerInternal(request));

        assertEquals("Username ya registrado.", exception.getMessage());
    }
}