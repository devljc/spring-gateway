package com.example.gateway.config.route;


import com.example.gateway.config.properties.RouteProperties;
import com.example.gateway.config.properties.RouteType;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.Function;

import static com.example.gateway.config.properties.RouteType.PUBLIC;


@Configuration
@RequiredArgsConstructor
public class RouteRegistryConfig {

    private final KeyResolver ipKeyResolver;
    private final GatewayFilter jwtClaimToHeaderFilter;  // 인증용 필터
    private final RedisRateLimiter rateLimiter;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder, RouteProperties routeProperties) {
        RouteLocatorBuilder.Builder routes = builder.routes();
        for (RouteProperties.RouteDefinition def : routeProperties.getRoutes()) {
            routes.route(def.getId(), routeSpec(def));
        }
        return routes.build();
    }

    private Function<PredicateSpec, Buildable<Route>> routeSpec(RouteProperties.RouteDefinition def) {
        String[] paths = def.getPaths().toArray(String[]::new);
        return r -> {
            BooleanSpec specBuilder = r.path(paths);
            RouteType type = def.getType();
            if (type == PUBLIC) return specBuilder.uri(def.getUri());
            switch (type) {
                case AUTHENTICATED -> specBuilder.filters(this::jwtClaimToHeaderFilterSpec);
                case PUBLIC_RATE_LIMIT -> specBuilder.filters(this::rateLimitSpec);
                case AUTHENTICATED_RATE_LIMIT -> specBuilder.filters(gatewayFilterSpec ->
                        rateLimitSpec(gatewayFilterSpec)
                                .filter(jwtClaimToHeaderFilter));
                default -> throw new IllegalStateException("Unexpected value: " + type);
            }
            return specBuilder.uri(def.getUri());
        };
    }

    private GatewayFilterSpec jwtClaimToHeaderFilterSpec(GatewayFilterSpec f) {
        return f.removeRequestHeader("Cookie")
                .filter(jwtClaimToHeaderFilter);
    }

    private GatewayFilterSpec rateLimitSpec(GatewayFilterSpec f) {
        return f.requestRateLimiter(config -> {
            config.setRateLimiter(rateLimiter);
            config.setKeyResolver(ipKeyResolver);
        });
    }
}



