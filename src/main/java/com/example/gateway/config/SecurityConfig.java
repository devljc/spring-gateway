package com.example.gateway.config;


import com.example.gateway.config.properties.RouteProperties;
import com.example.gateway.config.properties.RouteType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RouteProperties routeProperties;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(getPublicPaths()).permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                );
        return http.build();
    }

    private String[] getPublicPaths() {
        return routeProperties.getRoutes().stream()
                .filter(route -> route.getType() == RouteType.PUBLIC || route.getType() == RouteType.PUBLIC_RATE_LIMIT)
                .flatMap(route -> route.getPaths().stream())
                .toArray(String[]::new);
    }
}
