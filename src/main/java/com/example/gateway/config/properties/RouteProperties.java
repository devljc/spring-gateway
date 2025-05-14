package com.example.gateway.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "service")
public class RouteProperties {

    private List<RouteDefinition> routes;

    @Getter
    @Setter
    public static class RouteDefinition {
        private String id;
        private List<String> paths;
        private String uri;
        private RouteType type;
        private RateLimit rateLimit;

        @Getter
        @Setter
        public static class RateLimit {
            private int requestPerSecond;
            private int burst;
        }
    }
}
