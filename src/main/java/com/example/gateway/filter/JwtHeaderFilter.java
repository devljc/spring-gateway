package com.example.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Optional;

@Configuration
public class JwtHeaderFilter {

    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_USER_ROLE = "X-User-Role";
    private static final String DEFAULT_ROLE = "ROLE_USER";

    @Bean
    public GatewayFilter jwtClaimToHeaderFilter() {
        return (exchange, chain) -> exchange.getPrincipal()
                .flatMap(principal -> {
                    if (principal instanceof JwtAuthenticationToken token) {
                        Jwt jwt = token.getToken();
                        String userId = jwt.getSubject();
                        String role = Optional.ofNullable(jwt.getClaimAsString("role")).orElse(DEFAULT_ROLE);

                        ServerHttpRequest request = exchange.getRequest().mutate()
                                .header(HEADER_USER_ID, userId)
                                .header(HEADER_USER_ROLE, role)
                                .build();

                        return chain.filter(exchange.mutate().request(request).build());
                    }
                    return chain.filter(exchange);
                });
    }
}
