#!/bin/bash
set -e

echo "=== fedeherrera-starter-infra: Instalación local ==="
echo ""

# Verificar Java
if [ -z "$JAVA_HOME" ]; then
    echo "[WARN] JAVA_HOME no está definido. Se usará 'java' del PATH."
fi

# Verificar Maven
if ! command -v mvn &> /dev/null && [ ! -f "./mvnw" ]; then
    echo "[ERROR] No se encuentra 'mvn' en el PATH ni existe './mvnw'."
    echo "  Instala Maven o descarga el wrapper con: mvn -N wrapper:wrapper"
    exit 1
fi

MVN_CMD="./mvnw"
if ! command -v java &> /dev/null && [ ! -f "$MVN_CMD" ]; then
    MVN_CMD="mvn"
fi

echo "[INFO] Usando: $MVN_CMD"
echo "[INFO] Compilando e instalando artifact local..."
echo ""

$MVN_CMD clean install -DskipTests

echo ""
echo "=== Instalación completada ==="
echo "    GroupId:    com.fedeherrera.infra"
echo "    ArtifactId: api-infra-starter"
echo "    Version:    1.0.0"
echo ""
echo "Agrega la dependencia en tu proyecto:"
echo ""
echo "  <dependency>"
echo "      <groupId>com.fedeherrera.infra</groupId>"
echo "      <artifactId>api-infra-starter</artifactId>"
echo "      <version>1.0.0</version>"
echo "  </dependency>"
