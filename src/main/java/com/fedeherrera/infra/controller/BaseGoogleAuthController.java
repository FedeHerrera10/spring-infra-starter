package com.fedeherrera.infra.controller;

import com.fedeherrera.infra.dto.GoogleLoginRequest;
import com.fedeherrera.infra.dto.LoginResponse;
import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.service.auth.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/** 
 * Controlador base para Google Auth. 
 * Se deja abstracto para que el proyecto final lo herede con su entidad de usuario.
 */
@RequiredArgsConstructor
public abstract class BaseGoogleAuthController<T extends BaseUser, V extends BaseVerificationToken> {

    protected final AuthService<T,V> authService;

    @Operation(
        summary = "Iniciar sesión con Google",
        description = "Autentica a un usuario utilizando un token de identificación de Google"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Inicio de sesión exitoso",
            content = @Content(schema = @Schema(implementation = LoginResponse.class))),
        @ApiResponse(responseCode = "401", description = "Token de Google inválido"),
        @ApiResponse(responseCode = "400", description = "Solicitud inválida")
    })
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody GoogleLoginRequest request) {
        return authService.loginWithGoogle(request.idToken());
    }
}