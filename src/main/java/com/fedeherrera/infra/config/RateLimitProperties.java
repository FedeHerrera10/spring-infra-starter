package com.fedeherrera.infra.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "fedeherrera.infra.rate-limit")
public class RateLimitProperties {
    /** tokens per minute for login & register */
    @Min(1)
    private int auth = 5;
    /** tokens per minute for refresh endpoints */
    @Min(1)
    private int refresh = 20;
    /** fallback tokens per minute for any other endpoint */
    @Min(1)
    private int defaultLimit = 100;
}
