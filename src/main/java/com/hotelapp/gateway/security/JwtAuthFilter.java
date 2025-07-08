package com.hotelapp.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@Slf4j
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Value("${jwt.secret}")
    private String secretBase64;

    public static class Config {
    }

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getPath().value();

            log.debug("Processing request for path: {}", path);

            if (path.startsWith("/api/v1/auth/")) {
                log.debug("Auth path detected, skipping JWT validation");
                return chain.filter(exchange);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Unauthorized request - Missing or malformed Authorization header");
                return unauthorizedResponse(exchange, "Missing or malformed Authorization header");
            }

            String token = authHeader.substring(7);
            Claims claims;

            try {
                claims = extractClaims(token);
                log.info("JWT Token decoded successfully: Subject={}, Role={}",
                        claims.getSubject(), claims.get("role", String.class));
            } catch (io.jsonwebtoken.ExpiredJwtException e) {
                log.warn("JWT expired: {}", e.getMessage());
                return unauthorizedResponse(exchange, "Token expired");
            } catch (io.jsonwebtoken.MalformedJwtException e) {
                log.warn("Malformed JWT token: {}", e.getMessage());
                return unauthorizedResponse(exchange, "Malformed token");
            } catch (io.jsonwebtoken.JwtException e) {
                log.warn("JWT error: {}", e.getMessage());
                return unauthorizedResponse(exchange, "Invalid JWT token");
            } catch (Exception e) {
                log.error("Unexpected error during JWT validation: {}", e.getMessage());
                return unauthorizedResponse(exchange, "Authentication error");
            }

            ServerHttpRequest modifiedRequest = request
                    .mutate()
                    .header("X-User-Id", claims.getSubject())
                    .header("X-User-Email", claims.get("email", String.class))
                    .header("X-User-Role", claims.get("role", String.class))
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }


    private Claims extractClaims(String token) {
        byte[] keyBytes = Base64.getDecoder().decode(secretBase64);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json");

        String json = String.format("{\"error\": \"Unauthorized\", \"message\": \"%s\"}", message);
        DataBuffer buffer = response.bufferFactory().wrap(json.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
