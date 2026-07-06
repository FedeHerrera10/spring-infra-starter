# 🚀 API Infrastructure Starter

[![Java](https://img.shields.io/badge/Java-17%2B-007396?logo=java&logoColor=white)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.0-6DB33F?logo=spring&logoColor=white)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io/)

**Solución Integral para APIs REST Seguras con Spring Boot**

Boilerplate escalable diseñado para acelerar el ciclo de desarrollo (Time-to-Market). Incluye:

- **Auth Stack:** Spring Security + JWT + OAuth2 (Google/GitHub/Social).
- **User Management:** Flujos completos de Auth (Sign up, Login, Password Reset) con servicio de mensajería SMTP integrado.
- **DevOps Ready:** Monitoreo nativo con Micrometer y Prometheus para visualización de métricas.
- **Arquitectura:** Diseño basado en buenas prácticas para facilitar la escalabilidad horizontal.

## 🌟 Características Principales

### 🔐 Autenticación y Autorización

- Autenticación JWT con tokens de acceso y refresco
- Integración con Google OAuth2
- Manejo de roles y permisos
- Protección contra ataques CSRF y XSS

### 📊 Monitoreo y Métricas

- Integración con **Prometheus** para métricas en tiempo real
- **Grafana** para visualización de datos
- Health checks y métricas de la aplicación
- Métricas personalizadas de negocio

### 📧 Sistema de Correo Electrónico

- **Rate limiting** integrado
- Plantillas preconfiguradas para:
  - Verificación de cuenta
  - Restablecimiento de contraseña
  - Notificaciones del sistema
- Envío asíncrono de correos

### 🛠️ Endpoints Listos para Usar

- Registro y autenticación de usuarios
- Gestión de perfiles
- Administración de usuarios (para administradores)
- Documentación interactiva con **Swagger UI**

## 🚀 Comenzando

### Requisitos

- Java 17 o superior
- Maven 3.6+
- Docker y Docker Compose (opcional)
- PostgreSQL (o cualquier base de datos compatible con JPA)

### Instalación

## 📦 Instalación

1. **Clonar el repositorio**

   ```bash
   git clone [https://github.com/tu-usuario/api-infra-starter.git](https://github.com/tu-usuario/api-infra-starter.git)
   cd api-infra-starter
   ```

   **Compilar el Starter localmente:** En la raíz del proyecto starter, ejecuta:

   ```bash
       mvn clean install
   ```

2. **Agregar la dependencia en tu nuevo proyecto (`pom.xml`):**

   ```xml
   <dependency>
       <groupId>com.fedeherrera.infra</groupId>
       <artifactId>api-infra-starter</artifactId>
       <version>1.0.0</version>
   </dependency>
   ```

---

## 🚀 Guía de Uso Rápido

Para usar el starter, debes "aterrizar" los componentes genéricos en tu aplicación.

### 1. Definir tus Entidades

Tus entidades deben extender las clases base del starter para heredar la lógica de auditoría y seguridad.

Java

```Java
@Entity
public class User extends BaseUser {
    // Tus campos personalizados (ej. biografía, avatar)
}

@Entity
public class VerificationToken extends BaseVerificationToken {
    @OneToOne(fetch = FetchType.LAZY)
    private User user;
}

```

### 2. Crear los Repositorios

Simplemente extiende las interfaces base:

```Java
public interface UserRepository extends BaseUserRepository<User> {}
public interface TokenRepository extends BaseVerificationTokenRepository<VerificationToken> {}

```

### 3. Implementar los Servicios

Debes extender las implementaciones abstractas para decirle a Spring qué entidades usar:

```java
@Service
public class AppUserService extends UserServiceImpl<User, VerificationToken> {
    public AppUserService(UserRepository repo, VerificationService<User, VerificationToken> v, PasswordEncoder p) {
        super(repo, v, p);
    }

    @Override
    public User createNewInstance() {
        return new User();
    }
}

```

```java
@Service
public class AppVerificationService extends VerificationServiceImpl<User, VerificationToken> {

    // ✅ El constructor debe recibir ÚNICAMENTE el repositorio
    // No uses @RequiredArgsConstructo
    public AppVerificationService(TokenRepository tokenRepository) {
        super(tokenRepository);
    }

    @Override
    protected VerificationToken createTokenInstance(User user, String token, LocalDateTime expiresAt, String type) {
        return VerificationToken.builder()
                .user(user)
                .token(token)
                .expiresAt(expiresAt)
                .type(BaseVerificationToken.TokenType.valueOf(type))
                .build();
    }

    @Override
    protected User getUserFromToken(VerificationToken token) {

        return token.getUser();
    }
}

```

### 4. Configurar el Controlador

Expón los endpoints de autenticación extendiendo el controlador base:

```java
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController extends BaseAuthController<User, VerificationToken> {
    public AuthController(AuthService<User, VerificationToken> authService, VerificationService<User, VerificationToken> verificationService, AppUserService userService) {
        super(authService, verificationService, userService);
    }
}
```

---

## ⚙️ Archivo de Configuración Base (`application.yml`)

Copia este contenido en tu proyecto final (`src/main/resources/application.yml`). Este archivo ya está preparado para buscar variables de entorno y tiene valores por defecto para desarrollo local.

YAML

```yaml
spring:
  application:
    name: ${APP_NAME}

  datasource:
    url: ${DB_URL:jdbc:mysql://db:33066/name_database?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true}
    username: ${DB_USERNAME:admin}
    password: ${DB_PASSWORD:admin}
    driver-class-name: com.mysql.cj.jdbc.Driver

  jpa:
    database-platform: org.hibernate.dialect.MySQLDialect
    hibernate:
      ddl-auto: validate
    show-sql: true
    properties:
      hibernate:
        format_sql: true

  mail:
    host: ${SPRING_MAIL_HOST}
    port: ${SPRING_MAIL_PORT}
    username: ${SPRING_MAIL_USERNAME}
    password: ${SPRING_MAIL_PASSWORD}
    properties:
      mail:
        smtp:
          auth: ${SPRING_MAIL_PROPERTIES_MAIL_SMTP_AUTH:true}
          starttls:
            enable: ${SPRING_MAIL_PROPERTIES_MAIL_SMTP_STARTTLS_ENABLE:true}
    from: ${MAIL_FROM:no-reply@tuapp.com}

  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: [email, profile, openid]
            redirect-uri: "{baseUrl}/login/oauth2/code/google"

google:
  oauth2:
    client:
      id: ${GOOGLE_CLIENT_ID}
      secret: ${GOOGLE_CLIENT_SECRET}

server:
  port: ${SERVER_PORT:8080}

fedeherrera:
  infra:
    jwt:
      secret-key: ${JWT_SECRET}
      expiration: ${JWT_EXPIRATION:900000}
      refresh-expiration: ${JWT_REFRESH_EXPIRATION:604800000}

app:
  cors:
    allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000}
  security:
    verify-url: ${APP_SECURITY_VERIFY_URL:http://localhost:8080/api/v1/auth/verify}
    reset-url: ${APP_SECURITY_RESET_URL:http://localhost:8080/api/v1/auth/reset-password}

management:
  endpoints:
    web:
      exposure:
        include: "health,info,metrics,prometheus"
  endpoint:
    health:
      show-details: always
    prometheus:
      enabled: true
  metrics:
    tags:
      application: ${spring.application.name}

springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui.html
  show-actuator: true
  packages-to-scan: com.example.app,com.fedeherrera.infra
  paths-to-match: /**

logging:
  file:
    name: /app/logs/app.log
  level:
    com.fedeherrera.infra: DEBUG
    org.springframework.web: INFO
    org.hibernate.SQL: DEBUG
```

---

## 🔑 Variables de Entorno (`.env`)

Para que el sistema de logs (Loki) y las métricas funcionen correctamente, crea un archivo `.env` en la raíz de tu proyecto. Este archivo simula las variables que Docker inyectará en producción.

Fragmento de código

```
APP_NAME=name_app
DB_URL=jdbc:mysql://localhost:3306/nombre_base_datos?useSSL=false&serverTimezone=UTC
DB_USERNAME=usuario
DB_PASSWORD=contraseña
SPRING_PROFILES_ACTIVE=dev
SERVER_PORT=8080

# SMTP host
MAIL_HOST=servidor.smtp.ejemplo.com

# SMTP puerto
MAIL_PORT=587

# Usuario SMTP
MAIL_USER=tu_usuario_smtp

# Password SMTP
MAIL_PASSWORD=tu_contraseña_smtp

# From del email
MAIL_FROM=no-reply@ejemplo.com

MAIL_TLS=true
MAIL_AUTH=true

# URLs de la aplicación
APP_SECURITY_VERIFY_URL=https://tudominio.com/verify
APP_SECURITY_RESET_URL=https://tudominio.com/reset-password

# Configuración JWT
JWT_SECRET=reemplazar_con_tu_clave_secreta_segura_y_larga
JWT_EXPIRATION=900000            # 15 minutos
JWT_REFRESH_EXPIRATION=604800000 # 7 días

# Configuración OAuth2 Google
GOOGLE_CLIENT_ID=tu_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu_google_client_secret

# Orígenes permitidos (separados por coma si son varios)
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

```java

@SpringBootApplication(scanBasePackages = {

		"com.demo.app", // Tu paquete actual

		"com.fedeherrera.infra" // El paquete del Starter

})

// IMPORTANTE: También debes habilitar los repositorios del Starter

@EnableJpaRepositories(basePackages = {

		"com.demo.app.repository",

		"com.fedeherrera.infra.repository"

})

@EntityScan(basePackages = {

		"com.demo.app.entity",

		"com.fedeherrera.infra.entity"

})
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}

```

---

## 🔒 Personalización de Seguridad

El starter incluye una configuración de seguridad **default** que:

- Deshabilita CSRF
- Configura CORS desde `app.cors.allowed-origins`
- Establece sesiones **stateless** (JWT)
- Expone como públicos: `/api/v1/auth/**`, `/actuator/health`, `/actuator/info`, `/swagger-ui/**`, `/v3/api-docs/**`
- Conecta `JwtAuthFilter`, `RateLimitFilter`, `JwtAuthenticationEntryPoint` y `CustomAccessDeniedHandler`
- Provee beans de `PasswordEncoder` (BCrypt) y `AuthenticationManager`

### Cómo sobrescribir la seguridad

Si necesitas personalizar la configuración de seguridad, simplemente define un bean `SecurityFilterChain` en tu aplicación. El starter automáticamente usará tu bean en lugar del default:

```java
@Configuration
public class MySecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .cors(cors -> { /* tu config */ })
            .csrf(csrf -> csrf.disable())
            // ... tu configuración personalizada
            .build();
    }
}
```

Del mismo modo puedes sobrescribir `PasswordEncoder` o `AuthenticationManager` definiendo tus propios beans.
