package com.fedeherrera.infra;

import com.fedeherrera.infra.config.RateLimitProperties;
import com.fedeherrera.infra.filter.RateLimitFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Import;
import static org.assertj.core.api.Assertions.assertThat;

class AutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues(
                    "fedeherrera.infra.rate-limit.auth=5",
                    "fedeherrera.infra.rate-limit.refresh=20",
                    "fedeherrera.infra.rate-limit.default-limit=100");

    @Test
    void contextLoadsAndBeansPresent() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(RateLimitFilter.class);
            assertThat(context).hasSingleBean(RateLimitProperties.class);
        });
    }

    @Import({ RateLimitFilter.class, RateLimitProperties.class, com.fedeherrera.infra.config.JwtProperties.class })
    static class TestConfig {
    }
}
