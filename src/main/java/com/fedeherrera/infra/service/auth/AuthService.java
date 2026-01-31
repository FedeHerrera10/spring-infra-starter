package com.fedeherrera.infra.service.auth;

import com.fedeherrera.infra.dto.*;
import com.fedeherrera.infra.entity.*;
import com.fedeherrera.infra.exception.AuthException;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.service.GoogleTokenVerifierService;
import com.fedeherrera.infra.service.JwtService;
import com.fedeherrera.infra.service.role.RoleService;
import com.fedeherrera.infra.service.user.UserService;
import com.fedeherrera.infra.service.verfication.VerificationService;
import com.fedeherrera.infra.service.token.RefreshTokenService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService<T extends BaseUser, V extends BaseVerificationToken> { // <--- Usamos T para extensibilidad

    private final UserService<T> userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final VerificationService<T, V> verificationService;
    private final JwtService jwtService;

    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final GoogleTokenVerifierService googleTokenVerifierService;
    private final ApplicationEventPublisher eventPublisher; //
    // Permitimos que el proyecto final cambie las URLs desde application.properties
    @Value("${app.security.verify-url:http://localhost:8080/api/v1/auth/verify}")
    private String verifyUrl;

    @Value("${app.security.reset-url:http://localhost:8080/api/v1/auth/reset-password}")
    private String resetUrl;

    @Transactional
    public void registerPublic(PublicRegisterRequest request) {
        validateUniqueFields(request.getUsername(), request.getEmail());

        Role roleUser = roleService.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));

        // Usamos T para la creación.
        // Nota: Como T es genérico, necesitamos guardarlo a través del userService
        // que es el que conoce cómo instanciarlo o manejarlo.
        T user = userService.createNewInstance();
        user.setUsername(request.getUsername().trim().toLowerCase());
        user.setEmail(request.getEmail().trim().toLowerCase());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(false);
        user.setAccountNonLocked(true);
        user.setRoles(Set.of(roleUser));

        userService.save(user);

        BaseVerificationToken token = verificationService.createToken(user);

        // Preparamos los datos dinámicos
        Map<String, Object> props = Map.of(
                "url", verifyUrl + "?token=" + token.getToken(),
                "name", user.getFirstName());

        // Publicamos el evento
        eventPublisher.publishEvent(new EmailEvent(
                user.getEmail(),
                EmailTemplate.USER_VERIFICATION,
                props));

    }

    @Transactional
    public void registerInternal(AdminCreateUserRequest request) {

        if (userService.existsByUsername(request.getUsername())) {
            throw new RegistrationException("Username ya registrado.");
        }
        if (userService.existsByEmail(request.getEmail())) {
            throw new RegistrationException("Email ya registrado.");
        }

        Role roleUser = roleService.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));

        // Usamos T para la creación.
        // Nota: Como T es genérico, necesitamos guardarlo a través del userService
        // que es el que conoce cómo instanciarlo o manejarlo.
        T user = userService.createNewInstance();
        user.setUsername(request.getUsername().trim().toLowerCase());
        user.setEmail(request.getEmail().trim().toLowerCase());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(false);
        user.setAccountNonLocked(true);
        user.setRoles(Set.of(roleUser));

        userService.save(user);

    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

            UserPrincipal principal = (UserPrincipal) auth.getPrincipal();
            // El Principal nos devuelve la base, la casteamos a T
            @SuppressWarnings("unchecked")
            T user = (T) principal.getUser();

            if (user.getFailedAttempts() > 0) {
                userService.resetFailedAttempts(user.getId());
            }

            String accessToken = jwtService.generateToken(principal);
            String refreshToken = jwtService.generateRefreshToken(principal);

            refreshTokenService.createRefreshToken(user.getId(), refreshToken, "unknown", "unknown");
            String roleName = user.getRoles().stream()
                    .findFirst().map(Role::getName).orElse("ROLE_USER");

            return new LoginResponse(user.getUsername(), accessToken, refreshToken, roleName);

        } catch (BadCredentialsException e) {
            userService.registerFailedAttempt(request.getUsername());
            throw new AuthException("Credenciales inválidas");
        } catch (LockedException e) {
            throw new AuthException("Cuenta bloqueada por seguridad.");
        } catch (DisabledException e) {
            throw new AuthException("Usuario no verificado");
        }
    }

    @Transactional
    public LoginResponse loginWithGoogle(String googleToken) {
        try {
            GoogleIdToken.Payload payload = googleTokenVerifierService.verify(googleToken);
            if (payload == null)
                throw new AuthException("Token de Google inválido");

            String email = payload.getEmail();
            String name = (String) payload.get("name");

            T user = userService.findByEmail(email)
                    .orElseGet(() -> createGoogleUser(email, name));

            if (!user.isEnabled())
                throw new AuthException("El usuario está deshabilitado");

            UserPrincipal principal = new UserPrincipal(user);
            String accessToken = jwtService.generateToken(principal);
            String refreshToken = jwtService.generateRefreshToken(principal);

            return new LoginResponse(user.getUsername(), accessToken, refreshToken,
                    user.getRoles().stream().findFirst().map(Role::getName).orElse("ROLE_USER"));

        } catch (Exception e) {
            log.error("Error en Google Auth: ", e);
            throw new AuthException("Error durante la autenticación con Google");
        }
    }

    private T createGoogleUser(String email, String name) {
        String[] names = name.split(" ", 2);
        T user = userService.createNewInstance();
        user.setEmail(email.toLowerCase());
        user.setUsername(email.toLowerCase());
        user.setFirstName(names[0]);
        user.setLastName(names.length > 1 ? names[1] : "");
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
        user.setEnabled(true);
        user.setProvider(AuthProviderEnum.GOOGLE);

        Role userRole = roleService.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));
        user.setRoles(Set.of(userRole));

        return userService.save(user);
    }

    public LoginResponse refreshToken(String oldRefreshTokenValue, String ip, String userAgent) {
        // 1. Extraer el email del token viejo para buscar al usuario
        // (Nota: No validamos expiración aquí, el RefreshTokenService lo hará con la
        // DB)
        String userEmail = jwtService.extractUsername(oldRefreshTokenValue);

        // 2. Buscar al usuario real que implementa AuthUser
        var user = userService.findByUsername(userEmail)
                .orElseThrow(() -> new AuthException("Usuario no encontrado"));

        // 4. Generar nuevo Access Token (JWT de corta duración)
        UserPrincipal principal = new UserPrincipal(user);
        String newAccessToken = jwtService.generateToken(principal);
        String newRefreshToken = jwtService.generateRefreshToken(principal);

        // 3. ROTACIÓN: Delegamos la seguridad al servicio de persistencia
        // Este método:
        // - Verifica si el token existe en la DB.
        // - Verifica si ya fue usado (detección de robo).
        // - Verifica si el password cambió.
        // - Revoca el viejo y crea uno nuevo.
        RefreshToken nextRefreshTokenEntity = refreshTokenService.rotate(
                oldRefreshTokenValue,
                newRefreshToken,
                (AuthUser) user,
                ip,
                userAgent);

        // 5. Retornar la respuesta con el NUEVO refresh token
        return new LoginResponse(
                user.getUsername(),
                newAccessToken,
                nextRefreshTokenEntity.getToken(), // <--- Token nuevo generado en DB
                user.getRoles().stream()
                        .findFirst()
                        .map(Role::getName)
                        .orElse("ROLE_USER"));
    }

    public void resetPassword(T user) {

        V token = verificationService.createPasswordResetToken(user);
        user.setEnabled(false);
        userService.save(user);

        // Preparamos los datos dinámicos
        Map<String, Object> props = Map.of(
                "url", resetUrl + "?token=" + token.getToken(),
                "name", user.getFirstName());

        // Publicamos el evento
        eventPublisher.publishEvent(new EmailEvent(
                user.getEmail(),
                EmailTemplate.USER_VERIFICATION,
                props));
    }

    private void validateUniqueFields(String username, String email) {
        if (userService.existsByUsername(username))
            throw new RegistrationException("Username ya registrado.");
        if (userService.existsByEmail(email))
            throw new RegistrationException("Email ya registrado.");
    }
}