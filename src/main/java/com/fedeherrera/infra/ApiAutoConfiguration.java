package com.fedeherrera.infra;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

import com.fedeherrera.infra.config.GoogleAuthProperties;
import com.fedeherrera.infra.config.JwtProperties;

@AutoConfiguration
@ComponentScan(basePackages = "com.fedeherrera.infra")
@EnableConfigurationProperties({
    GoogleAuthProperties.class,
    JwtProperties.class
})
public class ApiAutoConfiguration {
}