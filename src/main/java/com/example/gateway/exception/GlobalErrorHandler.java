package com.example.gateway.exception;



import com.example.common.exception.ErrorCode;
import com.example.common.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Component
@Order(-2) // 필터보다 먼저 실행
@RequiredArgsConstructor
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ErrorCode errorCode = resolveErrorCode(ex);
        String message = resolveMessage(ex);

        log.warn("[Gateway Error] {} - {}", errorCode, message);
        exchange.getResponse().setStatusCode(HttpStatus.valueOf(errorCode.getStatus()));
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return writeAsBufferErrorResponse(exchange, errorCode, message);
    }

    private ErrorCode resolveErrorCode(Throwable ex) {
        if (ex instanceof ResponseStatusException statusEx) {
            int status = statusEx.getStatusCode().value();
            return ErrorCode.fromStatus(status);
        }
        return ErrorCode.INTERNAL_SERVER_ERROR;
    }

    private String resolveMessage(Throwable ex) {
        Throwable cause = ex.getCause();
        String message = Objects.requireNonNullElse(ex.getMessage(), "Unexpected error occurred");

        if (ex instanceof AuthenticationException) {
            if (cause instanceof JwtValidationException) return "Invalid JWT: " + cause.getMessage();
            if (message.toLowerCase().contains("expired")) return "Token has expired";
            return "Unauthorized: " + message;
        }

        if (ex instanceof ResponseStatusException statusEx) {
            return statusEx.getReason() != null ? statusEx.getReason() : statusEx.getStatusCode().toString();
        }
        return message;
    }

    private Mono<Void> writeAsBufferErrorResponse(ServerWebExchange exchange, ErrorCode errorCode, String message) {
        byte[] bytes = ApiResponse.errorJsonBytes(errorCode.getStatus(), message);
        DataBuffer wrap = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(wrap));
    }
}