# Spring Infra Starter 🚀

**Spring Infra Starter** es una librería de infraestructura personalizada diseñada para aplicaciones basadas en **Spring Boot 3.4+**. Su objetivo principal es centralizar y estandarizar seguridad , auditoria y trazabilidad de una aplicacion orientada mas que todo al desarrollo de API Rest , permitiendo enfocarse  exclusivamente en la lógica de negocio.

Al integrar este starter, cualquier proyecto  hereda automáticamente capacidades robustas de seguridad, resiliencia y monitoreo.

---

## ✨ Características Principales

* 🔐 **Seguridad Integrada:**
    * Filtro de autenticación **JWT** (JSON Web Token) preconfigurado.
    * Verificador de tokens de **Google OAuth2** listo para autenticación social.
    * Gestión centralizada de errores `401 Unauthorized` y `403 Forbidden` en formato JSON.
* 🚦 **Resiliencia y Rate Limiting:**
    * Protección contra ráfagas de tráfico y ataques de fuerza bruta mediante **Bucket4j**.
    * Algoritmo de *Token Bucket* aplicado por IP de origen.
* 📊 **Observabilidad (Grafana Ready):**
    * Configuración optimizada de **Spring Actuator**.
    * Exportación de métricas nativas para **Prometheus** mediante Micrometer.
* 📝 **Auditoría JPA Automatizada:**
    * Provee una clase base `AuditableEntity` para el registro automático de fechas de creación y modificación (`createdAt`, `updatedAt`).
* 🛠️ **Manejo Global de Excepciones:**
    * `GlobalExceptionHandler` que captura errores comunes y devuelve un esquema de respuesta estandarizado.

---

## 🛠️ Requisitos del Sistema

* **Java:** 17 o superior.
* **Maven:** 3.6 o superior.
* **Spring Boot:** 3.4.12 o superior.

---

## 🚀 Instalación

Para utilizar este starter en tu ecosistema local, debes "publicarlo" en tu repositorio local de Maven (`.m2`):

1. **Clona el proyecto:**
   ```bash
   git clone [https://github.com/tu-usuario/spring-infra-starter.git](https://github.com/tu-usuario/spring-infra-starter.git)
   cd spring-infra-starter
Instala localmente:
```bash
mvn clean install
```
Agrégalo a tu proyecto de negocio: En el pom.xml de tu API, añade la dependencia:

```XML

<dependency>
    <groupId>com.fedeherrera</groupId>
 <artifactId>spring-infra-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

⚙️ Configuración Requerida

El starter requiere que definas las siguientes propiedades en tu application.yml o archivo .env para inicializarse correctamente:

```YAML

fedeherrera:
  infra:
    jwt:
      secret-key: ${JWT_SECRET}          # Clave de firma (min. 32 caracteres)
      expiration: 900000                # Tiempo de acceso (ej. 15 min)
      refresh-expiration: 604800000     # Tiempo de refresh (ej. 7 días)
    google:
      client-id: ${GOOGLE_CLIENT_ID}    # Obtener de Google Cloud Console
    rate-limit:
      capacity: 10                      # Límite de peticiones permitidas
      tokens-per-minute: 10             # Tasa de recarga por minuto
```
📂 Estructura del Módulo

```Plaintext

com.fedeherrera.infra/
├── config/             # Auto-configuraciones de Beans y Propiedades
├── security/           # Filtros de seguridad y Handlers de Excepciones
├── service/            # Lógica de JWT, Google Auth y Rate Limiting
├── exception/          # Manejador Global de Errores (ControllerAdvice)
└── model/              # Entidades base y DTOs de respuesta de error
```

🧪 Cómo probar el Starter

Métricas: Accede a http://localhost:8080/actuator/prometheus para ver los contadores activos.

Rate Limit: Realiza peticiones rápidas a cualquier endpoint hasta recibir un error 429 Too Many Requests.

Auditoría: Haz que tus entidades extiendan de AuditableEntity para persistir fechas automáticamente.

👤 Autor
Fede Herrera - Backend Developer - GitHub