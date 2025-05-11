package com.example.gateway.config;


import com.leebak.gateway.config.ServiceRouteProperties.RouteDefinition;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class GatewayRouteConfig {

    private final com.leebak.gateway.config.ServiceRouteProperties serviceRouteProperties;
    private final GatewayFilter jwtClaimToHeaderFilter;

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {

        List<RouteDefinition> permitAll = serviceRouteProperties.getPermitAll();
        List<RouteDefinition> authenticated = serviceRouteProperties.getAuthenticated();

        validateUniqueRouteIds(permitAll, authenticated);

        RouteLocatorBuilder.Builder routes = builder.routes();
        addPublicRoutes(routes, permitAll);
        addAuthenticatedRoutes(routes, authenticated);
        return routes.build();
    }

    private void addPublicRoutes(RouteLocatorBuilder.Builder routes, List<RouteDefinition> permitAll) {
        for (RouteDefinition routeDefinition : permitAll) {
            String[] paths = routeDefinition.getPaths().toArray(String[]::new);
            routes.route(routeDefinition.getId(), r ->
                    r.path(paths).uri(routeDefinition.getUri())
            );
        }
    }

    private void addAuthenticatedRoutes(RouteLocatorBuilder.Builder routes, List<RouteDefinition> authenticated) {
        for (RouteDefinition routeDefinition : authenticated) {
            String[] paths = routeDefinition.getPaths().toArray(String[]::new);
            routes.route(routeDefinition.getId(), r ->
                    r.path(paths)
                            .filters(f -> f
                                    .removeRequestHeader("Cookie")
                                    .filter(jwtClaimToHeaderFilter))
                            .uri(routeDefinition.getUri())
            );
        }
    }

    @SafeVarargs
    private void validateUniqueRouteIds(List<RouteDefinition>... routeLists) {
        Set<String> ids = new HashSet<>();
        for (List<RouteDefinition> list : routeLists) {
            for (RouteDefinition def : list) {
                if (!ids.add(def.getId())) {
                    throw new IllegalStateException("Duplicate route ID detected: [" + def.getId() + "]");
                }
            }
        }
    }
}