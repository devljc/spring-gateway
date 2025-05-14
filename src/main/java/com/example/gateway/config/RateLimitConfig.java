package com.example.gateway.config;


import com.example.gateway.config.properties.RouteProperties;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Configuration
public class RateLimitConfig {

    @Bean
    public RedisRateLimiter redisRateLimiter(RouteProperties routeProperties) {
        // defaultReplenishRate: 초당 허용 요청 수
        // defaultBurstCapacity: 최대 버스트 처리 용량
        RedisRateLimiter defaultLimiter = new RedisRateLimiter(10, 20); // fallback 기본값
        // YAML 기반으로 라우트별 rate limit 설정 적용
        routeProperties.getRoutes().stream()
                .filter(route -> route.getRateLimit() != null)
                .forEach(route -> {
                    RouteProperties.RouteDefinition.RateLimit rateLimit = route.getRateLimit();
                    defaultLimiter.getConfig().put(route.getId(),
                            new RedisRateLimiter.Config()
                                    .setReplenishRate(rateLimit.getRequestPerSecond())
                                    .setBurstCapacity(rateLimit.getBurst()));
                });

        return defaultLimiter;
    }

    /**
     * IP 기반 Rate Limiter Key Resolver
     * @return KeyResolver
     * @implNote  X-Forwarded-For → remoteAddress → "unknown"
     */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String xfHeader = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
            if (xfHeader != null) {
                return Mono.just(xfHeader.split(",")[0].trim());
            }

            // getRemoteAddress()가 null일 수 있기 때문에 null 체크
            var remoteAddress = exchange.getRequest().getRemoteAddress();
            if (remoteAddress != null) {
                return Mono.just(remoteAddress.getAddress().getHostAddress());
            }

            return Mono.just("unknown-" + UUID.randomUUID()); // fallback
        };
    }

}
