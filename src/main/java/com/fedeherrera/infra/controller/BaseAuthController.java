package com.fedeherrera.infra.controller;

import com.fedeherrera.infra.dto.*;
import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.service.auth.AuthService;
import com.fedeherrera.infra.service.user.UserService;
import com.fedeherrera.infra.service.verfication.VerificationService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequiredArgsConstructor
public abstract class BaseAuthController<T extends BaseUser, V extends BaseVerificationToken> {

    protected final AuthService<T, V> authService;
    protected final VerificationService<T, V> verificationService;
    protected final UserService<T> userService;

    @Operation(summary = "Registro público de usuario")
    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@Valid @RequestBody PublicRegisterRequest request) {
        authService.registerPublic(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Usuario registrado. Por favor verifica tu email."));
    }

    @Operation(summary = "Crear usuario (Solo Admin)")
    @PostMapping(value = "/internal/create", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createUser(@Valid @RequestBody AdminCreateUserRequest request) {
        authService.registerInternal(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Usuario creado por administrador."));
    }

    @Operation(summary = "Iniciar sesión")
    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @Operation(summary = "Verificar cuenta con token")
    @PutMapping("/verify")
    public ResponseEntity<?> verificarCuenta(@RequestParam String token) {
        T user = verificationService.validateToken(token)
                .orElseThrow(() -> new RegistrationException("Token inválido o expirado"));

        user.setEnabled(true);
        userService.save(user);
        verificationService.deleteToken(token);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of("message", "Cuenta verificada correctamente"));
    }

    @Operation(summary = "Solicitar reset de contraseña")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> requestReset(@RequestBody @Valid EmailReset emailReset) {
        T user = userService.findByEmail(emailReset.getEmail())
                .orElseThrow(() -> new RegistrationException("Email no encontrado"));

        if (!user.isEnabled()) {
            throw new RegistrationException("Cuenta no verificada");
        }

        authService.resetPassword(user);

        return ResponseEntity.ok(Map.of("message", "Si el email existe, recibirás instrucciones"));
    }

    @Operation(summary = "Restablecer contraseña")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid DTOResetPassword resetPassword) {
        userService.resetPassword(resetPassword.getToken(), resetPassword.getNewPassword());
        return ResponseEntity.ok(Map.of("message", "Contraseña actualizada correctamente"));
    }

    @Operation(summary = "Refrescar Token JWT")
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue("refreshToken") String refreshToken, // Si usas Cookies
            HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        String ua = request.getHeader("User-Agent");

        return ResponseEntity.ok(authService.refreshToken(refreshToken, ip, ua));
    }
}