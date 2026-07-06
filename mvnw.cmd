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
@REM Maven Start Up Batch script
@REM
@REM Required ENV vars:
@REM JAVA_HOME - location of a JDK home dir
@REM
@REM Optional ENV vars
@REM M2_HOME - location of maven2's installed home dir
@REM MAVEN_BATCH_ECHO - set to 'on' to enable the echoing of the batch commands
@REM MAVEN_BATCH_PAUSE - set to 'on' to wait for a keystroke before ending
@REM MAVEN_OPTS - parameters passed to the Java VM when running Maven
@REM     e.g. to debug Maven itself, use
@REM set MAVEN_OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000
@REM MAVEN_SKIP_RC - flag to disable loading of mavenrc files
@REM ----------------------------------------------------------------------------

@REM Begin all REM lines with '@' in case MAVEN_BATCH_ECHO is 'on'
@echo off
@REM set title of command window
title %0
@REM enable echoing by setting MAVEN_BATCH_ECHO to 'on'
@if "%MAVEN_BATCH_ECHO%" == "on"  echo %MAVEN_BATCH_ECHO%

@REM set %HOME% to equivalent of $HOME
if "%HOME%" == "" (set "HOME=%HOMEDRIVE%%HOMEPATH%")

@REM Execute a user defined script before this one
if not "%MAVEN_SKIP_RC%" == "" goto skipRcPre
if exist "%HOME%\mavenrc_pre.bat" call "%HOME%\mavenrc_pre.bat"
:skipRcPre

set ERROR_CODE=0

@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" @setlocal
if "%OS%"=="WINNT" @setlocal

@REM ==== START VALIDATION ====
if not "%JAVA_HOME%" == "" goto OkJHome
echo.
echo Error: JAVA_HOME not found in your environment. >&2
echo Please set the JAVA_HOME variable in your environment to match the >&2
echo location of your Java installation. >&2
echo.
goto error

:OkJHome
if exist "%JAVA_HOME%\bin\java.exe" goto init
echo.
echo Error: JAVA_HOME is set to an invalid directory. >&2
echo JAVA_HOME = "%JAVA_HOME%" >&2
echo Please set the JAVA_HOME variable in your environment to match the >&2
echo location of your Java installation. >&2
echo.
goto error
@REM ==== END VALIDATION ====

:init

set MAVEN_CMD_LINE_ARGS=%*

@REM Find the project base dir, i.e. the directory that contains the folder ".mvn".
@REM Fallback to current working directory if not found.

set MAVEN_PROJECTBASEDIR=%MAVEN_BASEDIR%
if "%MAVEN_PROJECTBASEDIR%"=="" goto projectBaseDirNotFound
if not exist "%MAVEN_PROJECTBASEDIR%\.mvn\jvm.config" goto projectBaseDirNotFound

:foundProjectBaseDir
set MAVEN_PROJECTBASEDIR=%MAVEN_PROJECTBASEDIR%
goto endProjectBaseDir

:projectBaseDirNotFound
set MAVEN_PROJECTBASEDIR=%cd%
goto endProjectBaseDir

:endProjectBaseDir

set PROJECT_DIR=%MAVEN_PROJECTBASEDIR%

IF NOT "%MAVEN_PROJECTBASEDIR%"=="" goto endDetectBaseDir

set MAVEN_PROJECTBASEDIR=%cd%

:endDetectBaseDir

set "MVNW_REPOURL=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.2.0/maven-wrapper-3.2.0.jar"

set WRAPPER_JAR="%MAVEN_PROJECTBASEDIR%\.mvn\wrapper\maven-wrapper.jar"
if exist %WRAPPER_JAR% goto runmvn

set WRAPPER_URL=%MVNW_REPOURL%
if "%MVNW_REPOURL%"=="" (
  set WRAPPER_URL=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.2.0/maven-wrapper-3.2.0.jar
)

@echo Downloading Maven wrapper from %WRAPPER_URL%
if exist "%TMP%\maven-wrapper.jar" (
  @echo Found cached copy in %TMP%\maven-wrapper.jar
) else (
  if exist "%USERPROFILE%\.m2\wrapper\maven-wrapper.jar" (
    @echo Found cached copy in %USERPROFILE%\.m2\wrapper\maven-wrapper.jar
  ) else (
    @echo Downloading from %WRAPPER_URL%
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri %WRAPPER_URL% -OutFile %TMP%\maven-wrapper.jar}"
  )
)

if exist "%TMP%\maven-wrapper.jar" (
  copy /Y "%TMP%\maven-wrapper.jar" %WRAPPER_JAR% >nul
) else (
  if exist "%USERPROFILE%\.m2\wrapper\maven-wrapper.jar" (
    copy /Y "%USERPROFILE%\.m2\wrapper\maven-wrapper.jar" %WRAPPER_JAR% >nul
  )
)

if not exist %WRAPPER_JAR% (
  echo Failed to download Maven wrapper jar
  exit /b 1
)

:runmvn
set CLASSPATH=%CLASSPATH%;%WRAPPER_JAR%
set MAVEN_OPTS=%MAVEN_OPTS% -Dmaven.multiModuleProjectDirectory=%MAVEN_PROJECTBASEDIR%

@REM Execute Maven
"%JAVA_HOME%\bin\java.exe" %MAVEN_OPTS% -classpath "%CLASSPATH%" org.apache.maven.wrapper.MavenWrapperMain %MAVEN_CMD_LINE_ARGS%

:end
@REM set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" endlocal

:omega
