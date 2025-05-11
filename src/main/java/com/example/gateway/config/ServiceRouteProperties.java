package com.example.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "service.routes")
public class ServiceRouteProperties {

    private List<RouteDefinition> permitAll;
    private List<RouteDefinition> authenticated;


    @Getter
    @Setter
    public static class RouteDefinition {
        private String id;
        private List<String> paths;
        private String uri;
    }

    public String [] getPermitAllPaths() {
        if(permitAll != null && !permitAll.isEmpty()) {
            return permitAll.stream()
                    .flatMap(route -> route.getPaths().stream())
                    .toArray(String[]::new);
        }
        return new String[0];
    }
}
