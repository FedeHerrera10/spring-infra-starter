#!/bin/sh
# ----------------------------------------------------------------------------
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Apache Maven Wrapper startup batch script, version 3.2.0
#
# Optional ENV vars:
#   MVNW_REPOURL - repo url base for downloading maven distribution
#   MVNW_USERNAME/MVNW_PASSWORD - user and password for downloading maven
#   MVNW_VERBOSE - true: enable verbose log; others: silence the output
# ----------------------------------------------------------------------------

if [ "${MVNW_VERBOSE}" = true ] || [ "${MVNW_VERBOSE}" = debug ]; then
  set -x
fi

# set _MVNW_CMD, _MVNW_PROJECTBASEDIR and _MVNW_REPOURL
_MVNW_PROJECTBASEDIR="${MAVEN_BASEDIR:-$(cd "$(dirname "$0")" && pwd)}"
export _MVNW_PROJECTBASEDIR

if [ -z "${MVNW_REPOURL}" ]; then
  _MVNW_REPOURL="https://repo.maven.apache.org/maven2"
else
  _MVNW_REPOURL="${MVNW_REPOURL}"
fi

# Determine the Java command to use to start the JVM.
if [ -n "${JAVA_HOME}" ] ; then
  if [ -x "${JAVA_HOME}/jre/sh/java" ] ; then
    JAVACMD="${JAVA_HOME}/jre/sh/java"
  else
    JAVACMD="${JAVA_HOME}/bin/java"
  fi
  if [ ! -x "${JAVACMD}" ] ; then
    die "ERROR: JAVA_HOME is set to an invalid directory: ${JAVA_HOME}"
  fi
else
  JAVACMD="java"
  if ! command -v java >/dev/null 2>&1 ; then
    die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH."
  fi
fi

die() {
  echo "$@" 1>&2
  exit 1
}

verbose() {
  if [ "${MVNW_VERBOSE}" = true ] || [ "${MVNW_VERBOSE}" = debug ]; then
    echo "$@"
  fi
}

# Parse distributionUrl and optional distributionSha256Sum, requires .teledata/teledata
distributionUrl() {
  local _distributionUrl
  _distributionUrl=$(command sed -n 's/[!#]*/distributionUrl=\([^#]*\).*/\1/p' "${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/maven-wrapper.properties")
  echo "${_distributionUrl}"
}

distributionSha256Sum() {
  local _distributionSha256Sum
  _distributionSha256Sum=$(command sed -n 's/[!#]*/distributionSha256Sum=\([^#]*\).*/\1/p' "${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/maven-wrapper.properties")
  echo "${_distributionSha256Sum}"
}

wrapperUrl() {
  local _wrapperUrl
  _wrapperUrl=$(command sed -n 's/[!#]*/wrapperUrl=\([^#]*\).*/\1/p' "${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/maven-wrapper.properties")
  echo "${_wrapperUrl}"
}

# apply MVNW_USERNAME and MVNW_PASSWORD if present
case "${MVNW_USERNAME}${MVNW_PASSWORD}" in
  '') ;;
  *)
    if [ "${MVNW_VERBOSE}" = true ]; then
      echo "Using credentials from MVNW_USERNAME/MVNW_PASSWORD"
    fi
    _curl_options="-u ${MVNW_USERNAME}:${MVNW_PASSWORD} --silent --show-error --fail"
    _wget_options="--auth-no-challenge --quiet --user=${MVNW_USERNAME} --password=${MVNW_PASSWORD}"
    ;;
esac

# Prepare distribution download
_distributionUrl=$(distributionUrl)
_distributionSha256Sum=$(distributionSha256Sum)

# Determine the Maven Wrapper JAR and distribution
_wrapperJarPath="${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/maven-wrapper.jar"

if [ -r "${_wrapperJarPath}" ]; then
  verbose "Found existing .mvn/wrapper/maven-wrapper.jar"
else
  verbose "Could not find .mvn/wrapper/maven-wrapper.jar, downloading from $(wrapperUrl)"
  _wrapperUrl=$(wrapperUrl)
  if [ -n "${_wrapperUrl}" ]; then
    if command -v curl >/dev/null 2>&1; then
      verbose "Downloading with curl"
      eval "curl \${_curl_options} -o \"${_wrapperJarPath}\" \"${_wrapperUrl}\""
    elif command -v wget >/dev/null 2>&1; then
      verbose "Downloading with wget"
      eval "wget \${_wget_options} -O \"${_wrapperJarPath}\" \"${_wrapperUrl}\""
    else
      die "ERROR: No download tool found (curl or wget required)"
    fi
  fi

  # If jar download failed, try compiling MavenWrapperDownloader.java
  if [ ! -r "${_wrapperJarPath}" ] && [ -r "${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/MavenWrapperDownloader.java" ]; then
    verbose "Compiling MavenWrapperDownloader.java"
    _tmpdir=$(mktemp -d)
    if command -v javac >/dev/null 2>&1; then
      javac -d "${_tmpdir}" "${_MVNW_PROJECTBASEDIR}/.mvn/wrapper/MavenWrapperDownloader.java" && \
        (cd "${_tmpdir}" && java MavenWrapperDownloader) && \
        mv "${_tmpdir}/maven-wrapper.jar" "${_wrapperJarPath}"
      rm -rf "${_tmpdir}"
    fi
  fi
fi

if [ -r "${_wrapperJarPath}" ]; then
  exec "${JAVACMD}" \
    ${MAVEN_OPTS} \
    ${MAVEN_DEBUG_OPTS} \
    -classpath "${_wrapperJarPath}" \
    "-Dmaven.multiModuleProjectDirectory=${_MVNW_PROJECTBASEDIR}" \
    org.apache.maven.wrapper.MavenWrapperMain "$@"
else
  die "ERROR: Failed to download maven-wrapper.jar. Check your internet connection or the wrapperUrl in .mvn/wrapper/maven-wrapper.properties"
fi
