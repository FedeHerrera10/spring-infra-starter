# Etapa 1: Build
FROM maven:3.8.5-openjdk-17-slim AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

# Etapa 2: Runtime
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# --- ESTO SOLUCIONA TU PROBLEMA DE LOGS ---
# Creamos la carpeta de logs dentro del contenedor y le damos permisos totales
RUN mkdir -p /app/logs && chmod 777 /app/logs
# ------------------------------------------

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]