package com.fedeherrera.infra;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

import com.fedeherrera.infra.config.EmailAutoConfiguration;
import com.fedeherrera.infra.config.GoogleAuthProperties;
import com.fedeherrera.infra.config.JwtProperties;

@AutoConfiguration
@Import(EmailAutoConfiguration.class)
@EnableConfigurationProperties({
        GoogleAuthProperties.class,
        JwtProperties.class,

})
public class ApiAutoConfiguration {
}