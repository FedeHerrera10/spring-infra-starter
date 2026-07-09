@REM ----------------------------------------------------------------------------
@REM Licensed to the Apache Software Foundation (ASF) under one
@REM or more contributor license agreements.  See the NOTICE file
@REM distributed with this work for additional information
@REM regarding copyright ownership.  The ASF licenses this file
@REM to you under the Apache License, Version 2.0 (the
@REM "License"); you may not use this file except in compliance
@REM with the License.  You may obtain a copy of the License at
@REM
@REM    https://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing,
@REM software distributed under the License is distributed on an
@REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
@REM KIND, either express or implied.  See the License for the
@REM specific language governing permissions and limitations
@REM under the License.
@REM ----------------------------------------------------------------------------

@REM ----------------------------------------------------------------------------
@REM Apache Maven Wrapper startup batch script, version 3.2.0
@REM
@REM Optional ENV vars:
@REM   MVNW_REPOURL - repo url base for downloading maven distribution
@REM   MVNW_USERNAME/MVNW_PASSWORD - user and password for downloading maven
@REM   MVNW_VERBOSE - true: enable verbose log; others: silence the output
@REM ----------------------------------------------------------------------------

@IF "%__MVNW_ARG0_NAME__%"=="" (SET __MVNW_ARG0_NAME__=%~nx0)
@SET __MVNW_CMD__=
@SET __MVNW_ERROR__=
@SET __MVNW_PSMODULEP_SAVE=%PSModulePath%
@SET PSModulePath=
@FOR /F "usebackq tokens=1* delims==" %%A IN ("%~dp0\.mvn\wrapper\maven-wrapper.properties") DO @(
    IF "%%~A"=="wrapperUrl" SET "__MVNW_CMD__=%%~B"
    IF "%%~A"=="distributionUrl" SET "__MVNW_REPOURL__=%%~B"
)
@IF "%__MVNW_CMD__%"=="" SET "__MVNW_CMD__=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.2/maven-wrapper-3.3.2.jar"
@IF "%__MVNW_REPOURL__%"=="" SET "__MVNW_REPOURL__=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.6/apache-maven-3.9.6-bin.zip"
@SET __MVNW_JAR__=%~dp0\.mvn\wrapper\maven-wrapper.jar
@IF NOT EXIST %__MVNW_JAR__% (
    @IF DEFINED __MVNW_CMD__ (
        @ECHO Downloading from: %__MVNW_CMD__
        @powershell -Command "&{"^
			"$webclient = new-object System.Net.WebClient;"^
			"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $webclient.DownloadFile('%__MVNW_CMD__', '%__MVNW_JAR__%')"^
			"}"
        @IF %ERRORLEVEL% NEQ 0 (
            @SET __MVNW_ERROR__=Download failed
        )
    )
)
@IF "%__MVNW_ERROR__%" NEQ "" (
    @ECHO %__MVNW_ERROR__%
    @EXIT /B 1
)
@SET __MVNW_CMD__=
@SET __MVNW_ERROR__=
@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%
@SET __MVNW_PSMODULEP_SAVE=
@SET JAVA_EXE=%JAVA_HOME%\bin\java.exe
@IF NOT DEFINED JAVA_HOME (
    FOR %%I IN (java.exe) DO @SET JAVA_EXE=%%~$PATH:I
)
@"%JAVA_EXE%" %MAVEN_OPTS% %MAVEN_DEBUG_OPTS% -classpath "%__MVNW_JAR__%" "-Dmaven.multiModuleProjectDirectory=%~dp0" org.apache.maven.wrapper.MavenWrapperMain %*
