
package com.fedeherrera.infra.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.ForwardedHeaderFilter;

@Configuration
public class FilterRegistration {

    @Bean
    public FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
        FilterRegistrationBean<ForwardedHeaderFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new ForwardedHeaderFilter());
        // Es CRÍTICO que se ejecute antes que cualquier otro filtro de seguridad o rate limit
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE); 
        return bean;
    }
}