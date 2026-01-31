package com.fedeherrera.infra.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.HashSet;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fedeherrera.infra.config.TestSecurityConfig;
import com.fedeherrera.infra.dto.DTOResetPassword;
import com.fedeherrera.infra.dto.EmailEvent;
import com.fedeherrera.infra.dto.EmailReset;
import com.fedeherrera.infra.dto.LoginRequest;
import com.fedeherrera.infra.dto.LoginResponse;
import com.fedeherrera.infra.dto.PublicRegisterRequest;
import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;
import com.fedeherrera.infra.entity.Role;
import com.fedeherrera.infra.entity.UserPrincipal;
import com.fedeherrera.infra.exception.AuthException;
import com.fedeherrera.infra.exception.GlobalExceptionHandler;
import com.fedeherrera.infra.exception.RegistrationException;
import com.fedeherrera.infra.service.JwtService;
import com.fedeherrera.infra.service.auth.AuthService;
import com.fedeherrera.infra.service.role.RoleService;
import com.fedeherrera.infra.service.token.RefreshTokenService;
import com.fedeherrera.infra.service.user.UserService;
import com.fedeherrera.infra.service.verfication.VerificationService;
import com.fedeherrera.testUtil.AuhtControllerTest;
import com.fedeherrera.testUtil.TestUser;
import com.fedeherrera.testUtil.TestVerificationToken;

import jakarta.servlet.http.Cookie;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@WebMvcTest(AuhtControllerTest.class) // Solo carga este controlador
@ContextConfiguration(classes = { AuhtControllerTest.class, GlobalExceptionHandler.class })
@Import(TestSecurityConfig.class)
class BaseControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @MockBean
        private RefreshTokenService refreshTokenService;

        @MockBean
        private AuthService authService;

        @MockBean
        private VerificationService verificationService;

        @Mock
        private RoleService roleService;

        @MockBean
        private UserService userService;

        @MockBean
        private ApplicationEventPublisher eventPublisher;

        @MockBean
        private JwtService jwtService;

        @Mock
        private AuthenticationManager authenticationManager;

        @Mock
        private Authentication authentication;

        private Role role;
        private TestUser testUser;
        private TestVerificationToken token;
        private UserPrincipal principal;

        @BeforeEach
        void setup() {

                testUser = new TestUser();
                testUser.setUsername("test");
                testUser.setEmail("test");
                testUser.setPassword("");
                testUser.setFirstName("test");
                testUser.setLastName("test");
                testUser.setRoles(new HashSet<>());

                role = new Role();
                role.setId(1L);
                role.setName("ROLE_USER");

                token = new TestVerificationToken();
                token.setToken("test");
                token.setExpiresAt(null);

                principal = new UserPrincipal(testUser);
                authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        }

        @Test
        @DisplayName("Debe retornar 201 cuando el registro es exitoso")
        void testRegisterSuccess() throws Exception {
                // 1. GIVEN (Preparación)
                PublicRegisterRequest request = new PublicRegisterRequest();
                request.setUsername("user1");
                request.setEmail("user@mail.com");
                request.setPassword("Fede-2fede!");
                request.setFirstName("Federico");
                request.setLastName("Herrera");

                // No necesitamos mockear userService, roleService, etc.
                // Solo el método que el controlador llama.
                doNothing().when(authService).registerPublic(any(PublicRegisterRequest.class));

                // 2. WHEN (Acción)
                mockMvc.perform(post("/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))

                                // 3. THEN (Validación)
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.message")
                                                .value("Usuario registrado. Por favor verifica tu email."));

                // Verificamos que el controlador realmente "pasó la pelota" al servicio
                verify(authService, times(1)).registerPublic(any(PublicRegisterRequest.class));
        }

        @Test
        @DisplayName("Test register fail")
        public void testRegisterFail() throws Exception {
                PublicRegisterRequest request = new PublicRegisterRequest();
                request.setUsername("us");
                request.setEmail("user.com");
                request.setPassword("fede");
                request.setFirstName("Federico");
                request.setLastName("Herrera");

                mockMvc.perform(post("/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andDo(print())
                                .andExpect(status().isBadRequest())
                                // Validamos la estructura general
                                .andExpect(jsonPath("$.error").value("Validation Error"))
                                .andExpect(jsonPath("$.message").value("Los datos enviados no son válidos"))

                                // Validamos los errores específicos de los campos
                                .andExpect(jsonPath("$.validationErrors.email")
                                                .value("must be a well-formed email address"))
                                .andExpect(jsonPath("$.validationErrors.username").exists())
                                .andExpect(jsonPath("$.validationErrors.password").exists());

        }

        @Test
        @DisplayName("Test register fail user exist")
        public void testRegisterFailUserExist() throws Exception {
                PublicRegisterRequest request = new PublicRegisterRequest();
                request.setUsername("user");
                request.setEmail("user@mail.com");
                request.setPassword("Fede-2fede!");
                request.setFirstName("Federico");
                request.setLastName("Herrera");

                doThrow(new RegistrationException("Username ya registrado."))
                                .when(authService).registerPublic(any(PublicRegisterRequest.class));

                mockMvc.perform(post("/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andDo(print())
                                .andExpect(status().isBadRequest())
                                // Validamos la estructura general
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Username ya registrado."));
        }

        @Test
        @DisplayName("Test register fail email exist")
        public void testRegisterFailEmailExist() throws Exception {
                PublicRegisterRequest request = new PublicRegisterRequest();
                request.setUsername("user");
                request.setEmail("user@mail.com");
                request.setPassword("Fede-2fede!");
                request.setFirstName("Federico");
                request.setLastName("Herrera");

                doThrow(new RegistrationException("Email ya registrado."))
                                .when(authService).registerPublic(any(PublicRegisterRequest.class));

                mockMvc.perform(post("/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andDo(print())
                                .andExpect(status().isBadRequest())
                                // Validamos la estructura general
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Email ya registrado."));

        }

        @Test
        void login_DebeRetornarOk_CuandoCredencialesSonValidas() throws Exception {
                // 1. Preparar datos
                LoginRequest request = new LoginRequest("user", "pass123");
                LoginResponse response = new LoginResponse("user", "atoken", "rtoken", "ROLE_ADMIN");

                // 2. Definir comportamiento del Mock
                when(authService.login(any(LoginRequest.class))).thenReturn(response);

                // 3. Ejecutar y Verificar
                mockMvc.perform(post("/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.username").value("user"))
                                .andExpect(jsonPath("$.accessToken").value("atoken"));
        }

        @Test
        void login_credencialesInvalidas() throws Exception {
                LoginRequest request = new LoginRequest("user", "pass123");

                when(authService.login(any(LoginRequest.class))).thenThrow(new AuthException("Credenciales invalidas"));
                // 3. Ejecutar y Verificar
                mockMvc.perform(post("/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Credenciales invalidas"));
        }

        @Test
        void login_cuentaBloqueadaPorSerguridad() throws Exception {
                LoginRequest request = new LoginRequest("user", "pass123");

                when(authService.login(any(LoginRequest.class)))
                                .thenThrow(new AuthException("Cuenta bloqueada por seguridad"));
                // 3. Ejecutar y Verificar
                mockMvc.perform(post("/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Cuenta bloqueada por seguridad"));
        }

        @Test
        void login_usuarioNoVerificado() throws Exception {
                LoginRequest request = new LoginRequest("user", "pass123");

                when(authService.login(any(LoginRequest.class))).thenThrow(new AuthException("Usuario no verificado"));
                // 3. Ejecutar y Verificar
                mockMvc.perform(post("/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Usuario no verificado"));
        }

        @Test
        void verificarCuentaSuccess() throws Exception {

                when(verificationService.validateToken(any(String.class))).thenReturn(Optional.of(testUser));

                mockMvc.perform(put("/verify")
                                .param("token", "test"))
                                .andExpect(status().isAccepted())
                                .andExpect(jsonPath("$.message").value("Cuenta verificada correctamente"));
        }

        @Test
        void verificarCuentaFail() throws Exception {

                when(verificationService.validateToken(any(String.class)))
                                .thenThrow(new RegistrationException("Token invalido"));

                mockMvc.perform(put("/verify")
                                .param("token", "test"))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Token invalido"));
        }

        @Test
        void requestReset_DebeRetornarOk_CuandoUsuarioEsValido() throws Exception {
                // 1. Setup: Usuario existe y está habilitado
                EmailReset request = new EmailReset();
                request.setEmail("test@example.com");
                testUser.setEnabled(true);

                when(userService.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
                doNothing().when(authService).resetPassword(testUser);

                // 2. Ejecutar
                mockMvc.perform(post("/forgot-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Si el email existe, recibirás instrucciones"));

                // 3. Verificar que se llamó al servicio de reset
                verify(userService).findByEmail(any(String.class));
                verify(authService).resetPassword(testUser);
        }

        @Test
        void requestResetFail() throws Exception {
                EmailReset request = new EmailReset();
                request.setEmail("test@example.com");
                testUser.setEnabled(true);

                when(userService.findByEmail(any(String.class)))
                                .thenThrow(new RegistrationException("Email no encontrado"));

                mockMvc.perform(post("/forgot-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Email no encontrado"));
                // Verificamos que NUNCA se llamó al proceso de reset
                verify(authService, never()).resetPassword(any());
        }

        @Test
        void requestResetUserNotEnabled() throws Exception {
                EmailReset request = new EmailReset();
                request.setEmail("test@example.com");

                when(userService.findByEmail(any(String.class))).thenReturn(Optional.of(testUser));

                doNothing().when(authService).resetPassword(testUser);

                mockMvc.perform(post("/forgot-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Cuenta no verificada"));
                // Verificamos que NUNCA se llamó al proceso de reset
                verify(authService, never()).resetPassword(any());
        }

        @Test
        void resetPasswordSuccess() throws Exception {
                DTOResetPassword request = new DTOResetPassword();
                request.setToken("test");
                request.setNewPassword("pass123");

                doNothing().when(authService).resetPassword(any());

                mockMvc.perform(post("/reset-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.message").value("Contraseña actualizada correctamente"));
        }

        @Test
        void resetPasswordFail() throws Exception {
                DTOResetPassword request = new DTOResetPassword();
                request.setToken("test");
                request.setNewPassword("pass123");

                doThrow(new RegistrationException("Token invalido"))
                                .when(userService).resetPassword(anyString(), anyString());

                mockMvc.perform(post("/reset-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(request)))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").value("Business Logic Error"))
                                .andExpect(jsonPath("$.message").value("Token invalido"));
        }

        @Test
        void refreshTokenSuccess() throws Exception {
                LoginResponse loginResponse = LoginResponse.builder()
                                .accessToken("test")
                                .refreshToken("test")
                                .build();
                Cookie sessionCookie = new Cookie("refreshToken", "123456-abc");
                sessionCookie.setPath("/");
                sessionCookie.setHttpOnly(true);

                when(authService.refreshToken(anyString(), anyString(), anyString())).thenReturn(loginResponse);

                mockMvc.perform(post("/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("User-Agent", "test")
                                .cookie(sessionCookie)
                                .content(new ObjectMapper().writeValueAsString(loginResponse)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.accessToken").value("test"))
                                .andExpect(jsonPath("$.refreshToken").value("test"));
        }

        @Test
        void refreshTokenSuccessCookieNotFound() throws Exception {
                LoginResponse loginResponse = LoginResponse.builder()
                                .accessToken("test")
                                .refreshToken("test")
                                .build();
                ;

                when(authService.refreshToken(anyString(), anyString(), anyString())).thenReturn(loginResponse);

                mockMvc.perform(post("/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(new ObjectMapper().writeValueAsString(loginResponse)))
                                .andExpect(status().isInternalServerError());
        }

}