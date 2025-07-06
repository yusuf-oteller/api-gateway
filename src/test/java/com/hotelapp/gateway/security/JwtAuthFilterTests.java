package com.hotelapp.gateway.security;

import com.hotelapp.gateway.security.JwtAuthFilter.Config;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@ActiveProfiles("test")
public class JwtAuthFilterTests {

    private final String jwtSecret = "ZhV3+eY767wZQ4ce+qb8PbwanES3wA8XpBvAkC2ZiVA=";

    private JwtAuthFilter jwtAuthFilter;

    @BeforeEach
    void setUp() {
        jwtAuthFilter = new JwtAuthFilter();
        ReflectionTestUtils.setField(jwtAuthFilter, "secretBase64", jwtSecret);
    }

    private String createJwt(String userId, String email, String role) {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.builder()
                .subject(userId)
                .claim("email", email)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000))
                .signWith(key)
                .compact();
    }

    @Test
    void shouldRejectMissingAuthHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/hotels")
        );

        StepVerifier.create(jwtAuthFilter.apply(new Config()).filter(exchange, e -> Mono.empty()))
                .verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void shouldAcceptValidToken() {
        String token = createJwt("456", "test@example.com", "USER");

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/hotels")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        );

        StepVerifier.create(jwtAuthFilter.apply(new Config()).filter(exchange, mutatedExchange -> {
            String userId = mutatedExchange.getRequest().getHeaders().getFirst("X-User-Id");
            String email = mutatedExchange.getRequest().getHeaders().getFirst("X-User-Email");
            String role = mutatedExchange.getRequest().getHeaders().getFirst("X-User-Role");

            assertEquals("456", userId);
            assertEquals("test@example.com", email);
            assertEquals("USER", role);

            return Mono.empty();
        })).verifyComplete();
    }

    @Test
    void shouldSkipAuthForLoginPath() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/auth/login")
        );

        StepVerifier.create(jwtAuthFilter.apply(new Config()).filter(exchange, e -> Mono.empty()))
                .verifyComplete();

        assertNull(exchange.getResponse().getStatusCode());
    }
}
