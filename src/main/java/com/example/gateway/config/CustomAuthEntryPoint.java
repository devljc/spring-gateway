package com.example.gateway.config;

import com.example.core.response.ApiResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration
public class CustomAuthEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

        String message = resolveMessage(ex);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        Mono<DataBuffer> errorResponse = writeAsBufferErrorResponse(response, message);
        return response.writeWith(errorResponse);
    }

    private Mono<DataBuffer> writeAsBufferErrorResponse(ServerHttpResponse response, String message) {
        byte[] bytes =  ApiResponse.errorJsonBytes(HttpStatus.UNAUTHORIZED.value(), message);
        DataBuffer wrap = response.bufferFactory().wrap(bytes);
        return Mono.just(wrap);
    }

    private String resolveMessage(AuthenticationException ex) {
        Throwable cause = ex.getCause();
        if (cause instanceof JwtValidationException) return "Invalid JWT: " + cause.getMessage();
        if (ex.getMessage().toLowerCase().contains("expired")) return "Token has expired";
        return "Unauthorized: " + ex.getMessage();
    }
}