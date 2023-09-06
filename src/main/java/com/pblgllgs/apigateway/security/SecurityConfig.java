package com.pblgllgs.apigateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity security) throws Exception {
        return security
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange().anyExchange().authenticated()
                .and()
                .oauth2Login(Customizer.withDefaults())
                .build();
    }
}
